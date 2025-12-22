import { request } from "undici";
import net from "node:net";
import tls from "node:tls";
import dns from "node:dns/promises";

// -----------------------------
// Config
// -----------------------------
const PRAESID_API_BASE = process.env.PRAESID_API_BASE;
const AGENT_TOKEN = process.env.AGENT_TOKEN;
const AGENT_ID = process.env.AGENT_ID || "scanner-1";

const POLL_MS = parseInt(process.env.POLL_MS || "1500", 10);
const MAX_PORTS = parseInt(process.env.MAX_PORTS || "128", 10);
const CONNECT_TIMEOUT_MS = parseInt(process.env.CONNECT_TIMEOUT_MS || "1500", 10);
const OVERALL_TIMEOUT_MS = parseInt(process.env.OVERALL_TIMEOUT_MS || "90000", 10);

if (!PRAESID_API_BASE || !AGENT_TOKEN) {
  console.error("[agent] Missing PRAESID_API_BASE or AGENT_TOKEN");
  process.exit(1);
}
try { new URL(PRAESID_API_BASE); } catch {
  console.error(`[agent] PRAESID_API_BASE invalid: "${PRAESID_API_BASE}"`);
  process.exit(1);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// -----------------------------
// HTTP helpers
// -----------------------------
async function apiGet(path) {
  return await request(`${PRAESID_API_BASE}${path}`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${AGENT_TOKEN}`,
      "X-Agent-Id": AGENT_ID,
      Accept: "application/json",
    },
  });
}

async function apiPost(path, body) {
  return await request(`${PRAESID_API_BASE}${path}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${AGENT_TOKEN}`,
      "X-Agent-Id": AGENT_ID,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(body),
  });
}

// -----------------------------
// Findings helpers
// -----------------------------
function finding(category, severity, title, evidence = {}, recommendation = "") {
  return { category, severity, title, evidence, recommendation };
}

function uniq(arr) { return [...new Set(arr)]; }

function parsePorts(input) {
  if (!Array.isArray(input)) return [];
  return input
    .map((p) => Number(p))
    .filter((p) => Number.isInteger(p) && p > 0 && p <= 65535)
    .slice(0, MAX_PORTS);
}

function isHostname(s) {
  if (typeof s !== "string") return false;
  // very simple heuristic: contains letters and dots, not pure IPv4
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return false;
  return /^[a-z0-9.-]+$/i.test(s) && s.includes(".");
}

function daysUntil(dateStr) {
  if (!dateStr) return null;
  const ts = Date.parse(dateStr);
  if (!Number.isFinite(ts)) return null;
  return Math.floor((ts - Date.now()) / (1000 * 60 * 60 * 24));
}

// -----------------------------
// Network primitives
// -----------------------------
function tcpConnect(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = net.createConnection({ host, port });

    const done = (status, extra = {}) => {
      try { socket.destroy(); } catch {}
      resolve({
        status,
        host,
        port,
        rttMs: Date.now() - started,
        ...extra,
      });
    };

    socket.setTimeout(timeoutMs);
    socket.on("connect", () => done("open"));
    socket.on("timeout", () => done("timeout"));
    socket.on("error", (err) => done("closed", { error: err.code || err.message }));
  });
}

function readLineBanner(host, port, timeoutMs, writeFirst = null) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = net.createConnection({ host, port });
    let buf = "";

    const done = (status, extra = {}) => {
      try { socket.destroy(); } catch {}
      resolve({ status, host, port, rttMs: Date.now() - started, ...extra });
    };

    socket.setTimeout(timeoutMs);

    socket.on("connect", () => {
      if (writeFirst) {
        try { socket.write(writeFirst); } catch {}
      }
    });

    socket.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      if (buf.includes("\n")) {
        const line = buf.split("\n")[0].replace(/\r/g, "").trim();
        done("ok", { banner: line });
      }
      // guard very long
      if (buf.length > 4096) done("ok", { banner: buf.slice(0, 200) });
    });

    socket.on("timeout", () => done("timeout"));
    socket.on("error", (err) => done("closed", { error: err.code || err.message }));
  });
}

function tlsHandshake(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = tls.connect({
      host,
      port,
      servername: host, // SNI best-effort
      rejectUnauthorized: false,
      timeout: timeoutMs,
    });

    const done = (status, extra = {}) => {
      try { socket.destroy(); } catch {}
      resolve({ status, host, port, rttMs: Date.now() - started, ...extra });
    };

    socket.on("secureConnect", () => {
      const cert = socket.getPeerCertificate?.() || {};
      done("ok", {
        protocol: socket.getProtocol?.() || null,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError || null,
        cert: {
          subject: cert.subject || null,
          issuer: cert.issuer || null,
          valid_from: cert.valid_from || null,
          valid_to: cert.valid_to || null,
          subjectaltname: cert.subjectaltname || null,
          fingerprint256: cert.fingerprint256 || null,
        },
      });
    });

    socket.on("timeout", () => done("timeout"));
    socket.on("error", (err) => done("error", { error: err.code || err.message }));
  });
}

// -----------------------------
// Passive checks (15-ish)
// -----------------------------
async function checkDns(address, findings) {
  if (!isHostname(address)) return;
  try {
    const [A, AAAA, CNAME, MX, NS, TXT] = await Promise.allSettled([
      dns.resolve4(address),
      dns.resolve6(address),
      dns.resolveCname(address),
      dns.resolveMx(address),
      dns.resolveNs(address),
      dns.resolveTxt(address),
    ]);

    const out = {
      A: A.status === "fulfilled" ? A.value : null,
      AAAA: AAAA.status === "fulfilled" ? AAAA.value : null,
      CNAME: CNAME.status === "fulfilled" ? CNAME.value : null,
      MX: MX.status === "fulfilled" ? MX.value : null,
      NS: NS.status === "fulfilled" ? NS.value : null,
      TXT: TXT.status === "fulfilled" ? TXT.value.flat().slice(0, 50) : null,
    };

    findings.push(
      finding("dns", "info", "DNS records resolved", { address, records: out }, "Review DNS exposure and ensure records are expected.")
    );
  } catch (e) {
    findings.push(
      finding("dns", "info", "DNS resolution not available", { address, error: e?.message || String(e) }, "If using an IP, this is normal.")
    );
  }
}

async function checkTcpPorts(address, ports, findings) {
  const opens = [];
  for (const port of ports) {
    const r = await tcpConnect(address, port, CONNECT_TIMEOUT_MS);
    if (r.status === "open") opens.push(port);
  }
  findings.push(
    finding("ports", "info", "Open ports summary", { address, openPorts: opens }, "Close non-essential ports or restrict by firewall / IP allowlist.")
  );

  // highlight dangerous ports
  const dangerous = opens.filter((p) => [21, 23, 25, 110, 143, 3306, 5432, 6379, 27017].includes(p));
  if (dangerous.length) {
    findings.push(
      finding("ports", "high", "Potentially sensitive services exposed", { address, ports: dangerous },
        "If these services must be public, add auth + IP allowlist; otherwise restrict to private network.")
    );
  }
  return opens;
}

async function checkServiceBanners(address, openPorts, findings) {
  // SSH
  if (openPorts.includes(22)) {
    const r = await readLineBanner(address, 22, Math.max(CONNECT_TIMEOUT_MS * 2, 2000));
    if (r.status === "ok" && String(r.banner || "").startsWith("SSH-")) {
      findings.push(finding("ssh", "info", "SSH banner detected", { address, port: 22, banner: r.banner },
        "Restrict SSH by IP, disable password auth, prefer ed25519 keys."));
    } else if (r.status === "ok") {
      findings.push(finding("ssh", "medium", "Port 22 open but banner is not SSH", { address, port: 22, firstLine: r.banner },
        "Verify service running on port 22; unexpected service increases risk."));
    }
  }

  // FTP (21)
  if (openPorts.includes(21)) {
    const r = await readLineBanner(address, 21, Math.max(CONNECT_TIMEOUT_MS * 2, 2000));
    if (r.status === "ok") {
      findings.push(finding("banner", "high", "FTP service detected (banner)", { address, port: 21, banner: r.banner },
        "Avoid FTP on public internet; prefer SFTP/FTPS and restrict by IP."));
    }
  }

  // SMTP (25/587)
  for (const p of [25, 587]) {
    if (!openPorts.includes(p)) continue;
    const r = await readLineBanner(address, p, Math.max(CONNECT_TIMEOUT_MS * 2, 2000));
    if (r.status === "ok") {
      findings.push(finding("banner", "info", `SMTP service detected (port ${p})`, { address, port: p, banner: r.banner },
        "Ensure SMTP is intended and protected against abuse (SPF/DKIM/DMARC, rate limits)."));
    }
  }

  // Redis (6379) best-effort: send PING
  if (openPorts.includes(6379)) {
    const r = await readLineBanner(address, 6379, Math.max(CONNECT_TIMEOUT_MS * 2, 2000), "PING\r\n");
    findings.push(finding("banner", "high", "Redis port exposed", { address, port: 6379, response: r.banner || r.error || r.status },
      "Do not expose Redis publicly; bind to localhost/private network and require auth."));
  }

  // Mongo (27017) best-effort: just mark exposure
  if (openPorts.includes(27017)) {
    findings.push(finding("banner", "high", "MongoDB port exposed", { address, port: 27017 },
      "Do not expose databases publicly; restrict to private network / VPN."));
  }
}

async function checkTls(address, openPorts, findings) {
  const candidate = openPorts.includes(443) ? 443 : (openPorts.find((p) => [8443, 9443, 10443].includes(p)) ?? null);
  if (!candidate) return;

  const r = await tlsHandshake(address, candidate, Math.max(CONNECT_TIMEOUT_MS * 3, 3000));

  if (r.status !== "ok") {
    findings.push(finding("tls", "medium", "TLS handshake failed", { address, port: candidate, ...r },
      "If HTTPS should be enabled, verify firewall and TLS configuration."));
    return;
  }

  const daysLeft = daysUntil(r.cert?.valid_to);
  const proto = r.protocol || "unknown";

  findings.push(finding("tls", "info", "TLS reachable", {
    address, port: candidate, protocol: proto, valid_to: r.cert?.valid_to, issuer: r.cert?.issuer, subject: r.cert?.subject,
  }, "Keep TLS configuration up to date; rotate certificates before expiry."));

  if (daysLeft !== null && daysLeft < 14) {
    findings.push(finding("tls", "high", "TLS certificate expires soon", { address, port: candidate, daysLeft, valid_to: r.cert?.valid_to },
      "Renew the TLS certificate before it expires."));
  }

  // weak protocol heuristics (best-effort)
  if (typeof proto === "string" && (proto.includes("TLSv1") && !proto.includes("1.2") && !proto.includes("1.3"))) {
    findings.push(finding("tls", "high", "Old TLS protocol negotiated", { address, port: candidate, protocol: proto },
      "Disable TLS 1.0/1.1; allow TLS 1.2+ only."));
  }
}

async function httpFetchHead(url, method = "GET") {
  const res = await request(url, { method, headers: { "User-Agent": "PraesidInfraAgent/1.0", Accept: "*/*" } });
  const text = await res.body.text().catch(() => "");
  return { status: res.statusCode, headers: res.headers, body: text };
}

function pickHeader(headers, name) {
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
  return key ? headers[key] : null;
}

async function checkHttp(address, openPorts, findings) {
  const urls = [];
  if (openPorts.includes(80)) urls.push(`http://${address}/`);
  if (openPorts.includes(443)) urls.push(`https://${address}/`);
  // support custom http ports
  for (const p of [8080, 8000, 8888]) {
    if (openPorts.includes(p)) urls.push(`http://${address}:${p}/`);
  }
  for (const p of [8443, 9443]) {
    if (openPorts.includes(p)) urls.push(`https://${address}:${p}/`);
  }
  if (!urls.length) return;

  for (const url of urls.slice(0, 3)) {
    try {
      // 1) redirects chain (simple)
      let current = url;
      const chain = [current];
      for (let i = 0; i < 5; i++) {
        const r = await httpFetchHead(current, "GET");
        const loc = pickHeader(r.headers, "location");
        if (r.status >= 300 && r.status < 400 && loc) {
          const next = new URL(loc, current).toString();
          chain.push(next);
          current = next;
          continue;
        }
        // final response
        const headers = r.headers || {};
        const sec = {
          hsts: pickHeader(headers, "strict-transport-security"),
          csp: pickHeader(headers, "content-security-policy"),
          xfo: pickHeader(headers, "x-frame-options"),
          xcto: pickHeader(headers, "x-content-type-options"),
          refpol: pickHeader(headers, "referrer-policy"),
          perm: pickHeader(headers, "permissions-policy"),
        };

        findings.push(finding("http", "info", "HTTP response observed", {
          url, finalUrl: current, status: r.status, redirects: chain.length > 1 ? chain : null,
          server: pickHeader(headers, "server"),
          poweredBy: pickHeader(headers, "x-powered-by"),
          securityHeaders: sec,
        }, "Ensure recommended security headers are set (CSP, HSTS, etc.)."));

        // 2) missing security headers
        const missing = Object.entries(sec).filter(([, v]) => !v).map(([k]) => k);
        if (missing.length) {
          findings.push(finding("http", "medium", "Some HTTP security headers missing", { url: current, missing },
            "Add missing security headers where applicable (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)."));
        }

        // 3) methods via OPTIONS
        try {
          const opt = await httpFetchHead(current, "OPTIONS");
          const allow = pickHeader(opt.headers, "allow") || pickHeader(opt.headers, "access-control-allow-methods");
          if (allow) {
            findings.push(finding("http", "info", "HTTP methods advertised", { url: current, allow },
              "Review allowed methods; disable TRACE and unnecessary write methods on public endpoints."));
            if (String(allow).toUpperCase().includes("TRACE")) {
              findings.push(finding("http", "high", "TRACE method appears enabled", { url: current, allow },
                "Disable TRACE on your web server/reverse proxy."));
            }
            if (/(PUT|DELETE)/i.test(String(allow))) {
              findings.push(finding("http", "medium", "Potentially dangerous methods advertised", { url: current, allow },
                "Ensure PUT/DELETE are protected by auth and not exposed publicly."));
            }
          }
        } catch {}

        // 4) passive tech from HTML meta (best-effort)
        const ctype = pickHeader(headers, "content-type") || "";
        if (String(ctype).includes("text/html") && r.body) {
          const m = r.body.match(/<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/i);
          if (m?.[1]) {
            findings.push(finding("tech", "info", "HTML generator meta detected", { url: current, generator: m[1] },
              "Keep disclosed software versions up to date; consider reducing fingerprinting where appropriate."));
          }
        }

        break;
      }
    } catch (e) {
      findings.push(finding("http", "info", "HTTP check failed", { url, error: e?.message || String(e) },
        "If HTTP/HTTPS is expected, verify connectivity and TLS/cert settings."));
    }
  }
}

async function checkPassiveTechFromHeaders(findings) {
  // This is already embedded in HTTP findings; keep placeholder for future enrichment.
  // You can later add signature maps: nginx/apache/cloudflare, php, asp.net, etc.
  const servers = findings
    .filter((f) => f.category === "http" && f.evidence?.server)
    .map((f) => f.evidence.server);

  const powered = findings
    .filter((f) => f.category === "http" && f.evidence?.poweredBy)
    .map((f) => f.evidence.poweredBy);

  const uniqueServers = uniq(servers).filter(Boolean);
  const uniquePowered = uniq(powered).filter(Boolean);

  if (uniqueServers.length || uniquePowered.length) {
    findings.push(
      finding("tech", "info", "Passive technology signals", { serverHeaders: uniqueServers, xPoweredBy: uniquePowered },
        "Technology disclosure helps attackers; consider minimizing headers where feasible, and keep components patched.")
    );
  }
}

// -----------------------------
// Profiles
// -----------------------------
async function runConnectTest(job) {
  const started = Date.now();
  const target = job.target || {};
  const address = target.address;
  const sshPort = Number.isInteger(Number(target.sshPort)) ? Number(target.sshPort) : 22;

  const findings = [];
  if (!address) {
    return {
      status: "failed",
      findings: [finding("connect_test", "high", "Missing target address", { target }, "Provide a valid IP/hostname.")],
      meta: { durationMs: Date.now() - started, error: "missing_address" },
    };
  }

  // TCP connect + SSH banner only
  const tcp = await tcpConnect(address, sshPort, Math.max(CONNECT_TIMEOUT_MS, 1200));
  if (tcp.status !== "open") {
    findings.push(finding("connect_test", "high", "SSH port is not reachable",
      { address, sshPort, tcpStatus: tcp.status, error: tcp.error || null },
      "Check firewall/security list, port number, and that SSH is running."));
    return { status: "failed", findings, meta: { durationMs: Date.now() - started, error: "ssh_unreachable" } };
  }

  const banner = await readLineBanner(address, sshPort, Math.max(CONNECT_TIMEOUT_MS * 2, 2000));
  if (banner.status === "ok" && String(banner.banner || "").startsWith("SSH-")) {
    findings.push(finding("connect_test", "info", "SSH service detected",
      { address, sshPort, banner: banner.banner },
      "Connection test OK. (No authentication performed.)"));
    return { status: "completed", findings, meta: { durationMs: Date.now() - started } };
  }

  findings.push(finding("connect_test", "high", "Service on SSH port does not look like SSH",
    { address, sshPort, firstLine: banner.banner || null, status: banner.status },
    "Verify the SSH port; another service may be running there."));
  return { status: "failed", findings, meta: { durationMs: Date.now() - started, error: "no_ssh_banner" } };
}

async function runPassiveFull(job) {
  const started = Date.now();
  const target = job.target || {};
  const address = target.address;
  const ports = parsePorts(target.ports || []);
  const findings = [];

  if (!address) {
    return {
      status: "failed",
      findings: [finding("agent", "high", "Invalid target (missing address)", { target }, "Fix the target address.")],
      meta: { durationMs: Date.now() - started, error: "missing_address" },
    };
  }

  // DNS (if hostname)
  await checkDns(address, findings);

  // Ports: if none provided, use a safe default small set (v1)
  const portList = ports.length ? ports : [22, 80, 443, 8080, 8443].slice(0, MAX_PORTS);
  const openPorts = await checkTcpPorts(address, portList, findings);

  // Banners (services)
  await checkServiceBanners(address, openPorts, findings);

  // TLS (if relevant)
  await checkTls(address, openPorts, findings);

  // HTTP + headers + methods + redirects + tech peek
  await checkHttp(address, openPorts, findings);

  // Aggregate tech from headers
  await checkPassiveTechFromHeaders(findings);

  const durationMs = Date.now() - started;
  if (durationMs > OVERALL_TIMEOUT_MS) {
    return { status: "failed", findings, meta: { durationMs, error: "overall_timeout" } };
  }
  return { status: "completed", findings, meta: { durationMs } };
}

async function runJob(job) {
  const profile = job?.profile || "ssh_basic";

  if (profile === "connect_test") return await runConnectTest(job);

  // Default profile: "ssh_basic" -> we interpret as passive full (v1+)
  return await runPassiveFull(job);
}

// -----------------------------
// Main loop
// -----------------------------
async function main() {
  console.log(`[agent] praesid-infra-agent started (agentId=${AGENT_ID})`);
  console.log(`[agent] API base: ${PRAESID_API_BASE}`);

  while (true) {
    try {
      const res = await apiGet("/infra-scans/next");

      if (res.statusCode === 204) {
        await sleep(POLL_MS);
        continue;
      }

      const text = await res.body.text();

      if (res.statusCode !== 200) {
        console.error(`[agent] next job error ${res.statusCode}: ${text}`);
        await sleep(Math.min(POLL_MS * 2, 5000));
        continue;
      }

      let job;
      try {
        job = JSON.parse(text);
      } catch {
        console.error(`[agent] invalid JSON from /next: ${text}`);
        await sleep(Math.min(POLL_MS * 2, 5000));
        continue;
      }

      // Defensive checks
      if (!job || typeof job !== "object" || !job.jobId) {
        console.error(`[agent] /next returned invalid job payload: ${text}`);
        await sleep(Math.min(POLL_MS * 2, 5000));
        continue;
      }

      console.log(`[agent] got job ${job.jobId} profile=${job.profile || "ssh_basic"} target=${job?.target?.address}`);

      const result = await runJob(job);
      const payload = {
        status: result.status,
        findings: result.findings,
        meta: { ...(result.meta || {}), profile: job.profile || "ssh_basic" },
      };

      const post = await apiPost(`/infra-scans/${job.jobId}/results`, payload);
      const postText = await post.body.text();

      if (post.statusCode >= 200 && post.statusCode < 300) {
        console.log(`[agent] job ${job.jobId} reported (${result.status})`);
      } else {
        console.error(`[agent] report failed ${post.statusCode}: ${postText}`);
      }
    } catch (err) {
      console.error("[agent] loop error:", err?.stack || err);
      await sleep(Math.min(POLL_MS * 2, 5000));
    }
  }
}

main();
