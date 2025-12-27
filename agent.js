import { request } from "undici";
import net from "node:net";
import tls from "node:tls";
import dns from "node:dns/promises";
import { Client as SshClient } from "ssh2";
import "./load-env.js";

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
const METRICS_INTERVAL_MS = parseInt(process.env.METRICS_INTERVAL_MS || "60000", 10);

if (!PRAESID_API_BASE || !AGENT_TOKEN) {
  console.error("[agent] Missing PRAESID_API_BASE or AGENT_TOKEN");
  process.exit(1);
}
try { new URL(PRAESID_API_BASE); } catch {
  console.error(`[agent] PRAESID_API_BASE invalid: "${PRAESID_API_BASE}"`);
  process.exit(1);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const metricsState = {
  windowStart: Date.now(),
  processed: 0,
  success: 0,
  failure: 0,
  durationTotal: 0,
  durationCount: 0,
};
const metricsTimer = setInterval(() => flushMetrics(false), METRICS_INTERVAL_MS);
if (typeof metricsTimer.unref === "function") metricsTimer.unref();

const SSH_DEFAULT_USERNAME = process.env.AGENT_DEFAULT_SSH_USER || "praesid_audit";
const SSH_COMMAND_TIMEOUT_MS = parseInt(process.env.SSH_COMMAND_TIMEOUT_MS || "5000", 10);
const SSH_MAX_OUTPUT_BYTES = parseInt(process.env.SSH_MAX_OUTPUT_BYTES || "8000", 10);
const SSH_ALLOWED_COMMANDS = Object.freeze({
  uname: { command: "uname -a" },
  osRelease: { command: "cat /etc/os-release" },
  packagesDeb: { command: "dpkg -l | head -n 40" },
  packagesRpm: { command: "rpm -qa | head -n 40" },
  services: { command: "systemctl list-units --type=service --state=running --no-pager | head -n 25" },
  passwd: { command: "getent passwd | cut -d: -f1,3,7" },
  lastlog: { command: "last -n 5" },
  disks: { command: "df -h --output=source,size,used,avail,pcent,target" },
  ufw: { command: "ufw status" },
  iptables: { command: "iptables -L --line-numbers" },
  sshdConfig: { command: "grep -E '^(PasswordAuthentication|PermitRootLogin|PubkeyAuthentication|ChallengeResponseAuthentication)' /etc/ssh/sshd_config || true" },
  etcShadowPerm: { command: "ls -l /etc/shadow" },
  etcPasswdPerm: { command: "ls -l /etc/passwd" },
  cron: { command: "crontab -l 2>/dev/null || echo 'no crontab for current user'" },
  openPorts: { command: "ss -tunlp | head -n 40" },
});

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

function buildSummary(findings, meta = {}) {
  const now = new Date().toISOString();

  // -----------------
  // Runtime (tech stack passive)
  // -----------------
  const runtime = [];

/*   const osFinding = findings.find(f =>
    f.category === "ssh" && f.title?.toLowerCase().includes("ssh banner")
  );
  if (osFinding?.evidence?.banner) {
    runtime.push({
      label: "OS (estimé)",
      value: osFinding.evidence.banner,
      status: "ok",
    });
  } */

  const ssh = findings.find(f =>
    (f.category === "ssh" || f.category === "connect_test") &&
    (f.title || "").toLowerCase().includes("ssh")
  );

  const parsed = parseSshBanner(ssh?.evidence?.banner);

  if (parsed?.opensshVersion) {
    runtime.push({
      label: "OpenSSH",
      value: parsed.opensshVersion,
      status: "ok",
    });
  } else if (ssh?.evidence?.banner) {
    runtime.push({
      label: "SSH",
      value: ssh.evidence.banner,
      status: "ok",
    });
  }

  if (parsed?.distroHint) {
    runtime.push({
      label: "OS (indice)",
      value: parsed.distroPackageHint
        ? `${parsed.distroHint} (package ${parsed.distroPackageHint})`
        : parsed.distroHint,
      status: "ok",
    });
  } else {
    runtime.push({
      label: "OS (indice)",
      value: "Non déterminable sans authentification",
      status: "warn",
    });
  }


  const tlsFinding = findings.find(f => f.category === "tls" && f.severity === "info");
  if (tlsFinding?.evidence?.protocol) {
    runtime.push({
      label: "TLS",
      value: tlsFinding.evidence.protocol,
      status: "ok",
    });
  }

  // -----------------
  // Exposure
  // -----------------
  const exposure = [];

  const openPortsFinding = findings.find(f => f.title === "Open ports summary");
  if (openPortsFinding?.evidence?.openPorts?.length) {
    exposure.push({
      label: "Ports ouverts",
      detail: openPortsFinding.evidence.openPorts.join(", "),
      status: openPortsFinding.evidence.openPorts.length > 5 ? "warn" : "ok",
      statusLabel: openPortsFinding.evidence.openPorts.length > 5 ? "À réduire" : "Contrôlé",
    });
  }

  const sensitive = findings.filter(f =>
    f.severity === "high" &&
    ["ports", "banner"].includes(f.category)
  );

  if (sensitive.length) {
    exposure.push({
      label: "Services sensibles",
      detail: sensitive.map(s => s.title).join(" • "),
      status: "warn",
      statusLabel: "À surveiller",
    });
  } else {
    exposure.push({
      label: "Services sensibles",
      detail: "Aucun service critique exposé",
      status: "ok",
      statusLabel: "OK",
    });
  }

  // -----------------
  // Backups (v1 = inconnu)
  // -----------------
  const backups = {
    status: "warn",
    detail: "Impossible à vérifier sans authentification",
  };

  const summary = {
    timestamp: now,
    runtime,
    exposure,
    backups,
  };

  if (meta.systemInfo || meta.packages || meta.services || meta.diskUsage) {
    summary.sshAudit = {
      systemInfo: meta.systemInfo || null,
      packages: meta.packages || [],
      services: meta.services || [],
      users: meta.users || null,
      disks: meta.diskUsage || [],
      firewall: meta.firewall || null,
      sshConfig: meta.sshConfig || null,
      cron: meta.cron || [],
      openPorts: meta.openPortsDetailed || [],
      filePermissions: meta.filePermissions || null,
    };
  }

  return summary;
}


function parseSshBanner(banner) {
  if (!banner || typeof banner !== "string") return null;

  // Typical: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13
  const m = banner.match(/^SSH-\d+\.\d+-(.+)$/);
  const tail = m ? m[1] : banner;

  // Try OpenSSH_*
  const openssh = tail.match(/OpenSSH[_-]([0-9.]+p?\d*)/i);
  const opensshVersion = openssh?.[1] || null;

  // Distro hints (best effort)
  const distro =
    /ubuntu/i.test(tail) ? "Ubuntu" :
    /debian/i.test(tail) ? "Debian" :
    /centos/i.test(tail) ? "CentOS" :
    /fedora/i.test(tail) ? "Fedora" :
    /alpine/i.test(tail) ? "Alpine" :
    null;

  // Package suffix after distro name, e.g. "Ubuntu-3ubuntu0.13"
  let pkg = null;
  const pkgM = tail.match(/Ubuntu-([0-9][A-Za-z0-9.+~-]*)/i);
  if (pkgM?.[1]) pkg = pkgM[1];

  return {
    raw: banner,
    opensshVersion,
    distroHint: distro,
    distroPackageHint: pkg,
  };
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
// SSH helpers
// -----------------------------
function normalizePrivateKey(raw) {
  if (!raw) return null;
  const text = raw.toString().trim();
  if (text.includes("BEGIN")) return text;
  try {
    const decoded = Buffer.from(text, "base64").toString("utf8");
    return decoded.includes("BEGIN") ? decoded : text;
  } catch {
    return text;
  }
}

function sanitizeOutput(value, maxBytes = SSH_MAX_OUTPUT_BYTES) {
  if (!value) return "";
  const clean = value.replace(/[^\x09\x0A\x0D\x20-\x7E]/g, "");
  if (Buffer.byteLength(clean, "utf8") <= maxBytes) {
    return clean.trim();
  }
  return clean.slice(0, maxBytes).trim();
}

function linesFromOutput(value, limit = 50) {
  return sanitizeOutput(value)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(0, limit);
}

function parseOsRelease(output) {
  const entries = {};
  linesFromOutput(output, 40).forEach((line) => {
    const idx = line.indexOf("=");
    if (idx === -1) return;
    const key = line.slice(0, idx).replace(/"/g, "").trim();
    const val = line.slice(idx + 1).replace(/"/g, "").trim();
    if (key) entries[key] = val;
  });
  return entries;
}

function parseSshConfig(output) {
  const settings = {};
  linesFromOutput(output, 40).forEach((line) => {
    const [key, value] = line.split(/\s+/);
    if (!key) return;
    settings[key.trim()] = (value || "").trim().toLowerCase();
  });
  return settings;
}

function parseDiskUsage(output) {
  const lines = linesFromOutput(output, 40);
  if (lines.length <= 1) return [];
  const withoutHeader = lines.slice(1);
  return withoutHeader.map((line) => {
    const parts = line.split(/\s+/).filter(Boolean);
    if (parts.length < 6) return null;
    const [filesystem, size, used, avail, percent, target] = parts.slice(0, 6);
    return {
      filesystem,
      size,
      used,
      avail,
      percent,
      target,
    };
  }).filter(Boolean);
}

function connectSshClient(options) {
  const { host, port, username, privateKey, passphrase } = options;
  const readyTimeout = Number.parseInt(process.env.SSH_READY_TIMEOUT_MS || "8000", 10);
  return new Promise((resolve, reject) => {
    const client = new SshClient();
    const timer = setTimeout(() => {
      client.destroy();
      reject(new Error("ssh_connect_timeout"));
    }, readyTimeout + 2000);
    client.on("ready", () => {
      clearTimeout(timer);
      resolve(client);
    });
    client.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    client.connect({
      host,
      port,
      username,
      privateKey,
      passphrase,
      readyTimeout,
      keepaliveInterval: 5000,
      keepaliveCountMax: 2,
      tryKeyboard: false,
    });
  });
}

function runAllowedCommand(ssh, commandKey, timeoutMs = SSH_COMMAND_TIMEOUT_MS) {
  const descriptor = SSH_ALLOWED_COMMANDS[commandKey];
  if (!descriptor) {
    return Promise.reject(new Error(`Command not allowed: ${commandKey}`));
  }
  console.log(`[agent][debug] ssh exec -> ${commandKey}: ${descriptor.command}`);
  return new Promise((resolve, reject) => {
    ssh.exec(descriptor.command, (err, stream) => {
      if (err) return reject(err);
      const started = Date.now();
      let stdout = "";
      let stderr = "";
      let resolved = false;
      const timer = setTimeout(() => {
        if (resolved) return;
        resolved = true;
        try { stream.close(); } catch {}
        reject(new Error("command_timeout"));
      }, timeoutMs);
      const finish = (error, exitCode) => {
        if (resolved) return;
        resolved = true;
        clearTimeout(timer);
        if (error) return reject(error);
        resolve({
          stdout: sanitizeOutput(stdout, descriptor.maxBytes || SSH_MAX_OUTPUT_BYTES),
          stderr: sanitizeOutput(stderr, descriptor.maxBytes || Math.floor(SSH_MAX_OUTPUT_BYTES / 2)),
          exitCode,
          tookMs: Date.now() - started,
        });
      };
      stream.on("data", (chunk) => {
        stdout += chunk.toString("utf8");
        if (Buffer.byteLength(stdout, "utf8") > (descriptor.maxBytes || SSH_MAX_OUTPUT_BYTES)) {
          stdout = stdout.slice(0, descriptor.maxBytes || SSH_MAX_OUTPUT_BYTES);
        }
      });
      stream.stderr.on("data", (chunk) => {
        stderr += chunk.toString("utf8");
      });
      stream.on("close", (code) => finish(null, code));
      stream.on("error", (streamErr) => finish(streamErr));
    });
  });
}

async function runSshAudit(job) {
  const started = Date.now();
  const target = job.target || {};
  const credentials = job.credentials || {};
  const host = target.address || credentials.host || credentials.hostname;
  const port = Number.parseInt(credentials.port || target.port || "22", 10);
  const username = credentials.username || target.username || SSH_DEFAULT_USERNAME;
  const privateKey = normalizePrivateKey(credentials.privateKey || credentials.key || process.env.AGENT_SSH_KEY);
  const passphrase = credentials.passphrase ? String(credentials.passphrase) : undefined;

  if (!host || !privateKey) {
    return {
      status: "failed",
      findings: [
        finding("ssh_auth", "high", "Identifiants SSH manquants", { host, username }, "Fournissez un hôte et une clé privée pour l’audit SSH."),
      ],
      meta: { durationMs: 0, error: "missing_credentials" },
    };
  }

  let ssh;
  try {
    ssh = await connectSshClient({ host, port, username, privateKey, passphrase });
  } catch (error) {
    return {
      status: "failed",
      findings: [
        finding("ssh_auth", "high", "Connexion SSH impossible", { host, port, username, error: error.message },
          "Vérifiez la clé privée, l’utilisateur et l’accessibilité SSH (port 22)."),
      ],
      meta: { durationMs: Date.now() - started, error: error.message || "ssh_connect_error" },
    };
  }

  const findings = [];
  const meta = {};

  try {
    const osRelease = await runAllowedCommand(ssh, "osRelease").catch(() => ({ stdout: "" }));
    const kernel = await runAllowedCommand(ssh, "uname").catch(() => ({ stdout: "" }));
    const packagesDeb = await runAllowedCommand(ssh, "packagesDeb").catch(() => ({ stdout: "" }));
    const packagesRpm = await runAllowedCommand(ssh, "packagesRpm").catch(() => ({ stdout: "" }));
    const services = await runAllowedCommand(ssh, "services").catch(() => ({ stdout: "" }));
    const passwd = await runAllowedCommand(ssh, "passwd").catch(() => ({ stdout: "" }));
    const lastlog = await runAllowedCommand(ssh, "lastlog").catch(() => ({ stdout: "" }));
    const disksRaw = await runAllowedCommand(ssh, "disks").catch(() => ({ stdout: "" }));
    const ufw = await runAllowedCommand(ssh, "ufw").catch(() => ({ stdout: "" }));
    const iptables = await runAllowedCommand(ssh, "iptables").catch(() => ({ stdout: "" }));
    const sshdConfig = await runAllowedCommand(ssh, "sshdConfig").catch(() => ({ stdout: "" }));
    const shadowPerm = await runAllowedCommand(ssh, "etcShadowPerm").catch(() => ({ stdout: "" }));
    const passwdPerm = await runAllowedCommand(ssh, "etcPasswdPerm").catch(() => ({ stdout: "" }));
    const cron = await runAllowedCommand(ssh, "cron").catch(() => ({ stdout: "" }));
    const openPorts = await runAllowedCommand(ssh, "openPorts").catch(() => ({ stdout: "" }));

    meta.systemInfo = {
      kernel: sanitizeOutput(kernel.stdout),
      osRelease: parseOsRelease(osRelease.stdout),
    };
    meta.packages = packagesDeb.stdout ? linesFromOutput(packagesDeb.stdout, 40) : linesFromOutput(packagesRpm.stdout, 40);
    meta.services = linesFromOutput(services.stdout, 25);
    meta.users = {
      accounts: linesFromOutput(passwd.stdout, 40),
      lastLogins: linesFromOutput(lastlog.stdout, 10),
    };
    meta.diskUsage = parseDiskUsage(disksRaw.stdout);
    meta.firewall = {
      ufw: sanitizeOutput(ufw.stdout),
      iptables: linesFromOutput(iptables.stdout, 40),
    };
    meta.filePermissions = {
      shadow: sanitizeOutput(shadowPerm.stdout),
      passwd: sanitizeOutput(passwdPerm.stdout),
    };
    meta.cron = linesFromOutput(cron.stdout, 20);
    meta.openPortsDetailed = linesFromOutput(openPorts.stdout, 40);
    meta.sshConfig = parseSshConfig(sshdConfig.stdout);

    // Findings
    findings.push(finding("ssh_audit", "info", "Audit SSH complété", { host, username }, "Vérifiez les résultats détaillés."));

    if (meta.firewall.ufw.toLowerCase().includes("inactive")) {
      findings.push(finding("firewall", "medium", "Pare-feu UFW inactif", { ufw: meta.firewall.ufw }, "Activez UFW ou équivalent et restreignez les accès."));
    }

    const sshConfig = meta.sshConfig || {};
    if (sshConfig.PasswordAuthentication === "yes") {
      findings.push(finding("ssh_config", "high", "PasswordAuthentication activé", {}, "Désactivez les mots de passe, n’autorisez que les clés."));
    }
    if (sshConfig.PermitRootLogin === "yes") {
      findings.push(finding("ssh_config", "high", "PermitRootLogin autorisé", {}, "Désactivez l’accès direct root via SSH."));
    }
    if (sshConfig.PubkeyAuthentication === "no") {
      findings.push(finding("ssh_config", "medium", "PubkeyAuthentication désactivé", {}, "Activez l’authentification par clé publique."));
    }

    const disksWarn = (meta.diskUsage || []).filter((disk) => {
      const pct = parseInt(String(disk.percent || "").replace("%", ""), 10);
      return Number.isFinite(pct) && pct >= 90;
    });
    if (disksWarn.length) {
      findings.push(
        finding("disk", "medium", "Espace disque critique", { disks: disksWarn }, "Libérez de l’espace ou étendez le volume (>90%).")
      );
    }

    const shadowPermText = meta.filePermissions.shadow || "";
    if (shadowPermText && !shadowPermText.startsWith("-rw-------")) {
      findings.push(
        finding("permissions", "high", "/etc/shadow permissions non conformes", { shadowPerm: shadowPermText },
          "Restreignez /etc/shadow à 600 et root:shadow.")
      );
    }

    if (!meta.cron.length) {
      findings.push(finding("cron", "info", "Aucun cron pour l’utilisateur courant", {}, "Ajoutez des tâches planifiées si nécessaire."));
    }

    if (meta.openPortsDetailed.length) {
      findings.push(
        finding("ports", "info", "Ports ouverts (ss -tunlp)", { ports: meta.openPortsDetailed.slice(0, 20) },
          "Vérifiez que seuls les services nécessaires sont exposés.")
      );
    }

    return {
      status: "completed",
      findings,
      meta: {
        ...meta,
        durationMs: Date.now() - started,
        host,
        username,
      },
    };
  } catch (error) {
    return {
      status: "failed",
      findings: [
        finding("ssh_audit", "high", "Erreur lors de l’audit SSH", { host, error: error.message },
          "Revoyez la configuration SSH ou contactez le support Praesid."),
      ],
      meta: { ...meta, durationMs: Date.now() - started, error: error.message || "ssh_audit_error" },
    };
  } finally {
    try { ssh.end(); } catch {}
  }
}

async function runSshConnectivityTest(job) {
  const started = Date.now();
  const target = job.target || {};
  const credentials = job.credentials || {};
  const host = target.address || credentials.host || credentials.hostname;
  const port = Number.parseInt(credentials.port || target.port || "22", 10);
  const username = credentials.username || target.username || SSH_DEFAULT_USERNAME;
  const privateKey = normalizePrivateKey(credentials.privateKey || credentials.key || process.env.AGENT_SSH_KEY);
  const passphrase = credentials.passphrase ? String(credentials.passphrase) : undefined;

  console.log("[agent][debug] ssh_test privateKey snippet:", privateKey ? `${privateKey.slice(0, 64)}...` : "missing");

  if (!host || !privateKey) {
    return {
      status: "failed",
      findings: [
        finding("ssh_test", "high", "Informations SSH incomplètes", { host, username },
          "Fournissez l'hôte, l'utilisateur et la clé privée pour tester la connexion SSH."),
      ],
      meta: { durationMs: 0, error: "missing_credentials" },
    };
  }

  try {
    const ssh = await connectSshClient({ host, port, username, privateKey, passphrase });
    try { ssh.end(); } catch {}
    return {
      status: "completed",
      findings: [
        finding("ssh_test", "info", "Connexion SSH établie", { host, port, username },
          "La connexion SSH fonctionne avec ces identifiants."),
      ],
      meta: { durationMs: Date.now() - started },
    };
  } catch (error) {
    return {
      status: "failed",
      findings: [
        finding("ssh_test", "high", "Connexion SSH impossible", { host, port, username, error: error.message },
          "Vérifiez l’utilisateur, la clé privée et l’accès réseau au port SSH."),
      ],
      meta: { durationMs: Date.now() - started, error: error.message || "ssh_test_error" },
    };
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
  if (profile === "ssh_test") return await runSshConnectivityTest(job);
  if (profile === "ssh_audit") return await runSshAudit(job);

  // Default profile: "ssh_basic" -> we interpret as passive full (v1+)
  return await runPassiveFull(job);
}

function recordJobMetrics(status, durationMs = 0) {
  metricsState.processed += 1;
  if (status === "completed") {
    metricsState.success += 1;
  } else {
    metricsState.failure += 1;
  }
  if (Number.isFinite(durationMs) && durationMs > 0) {
    metricsState.durationTotal += durationMs;
    metricsState.durationCount += 1;
  }
}

function flushMetrics(force = false) {
  const now = Date.now();
  const elapsed = now - metricsState.windowStart;
  if (!force && elapsed < METRICS_INTERVAL_MS) return;
  const processed = metricsState.processed;
  if (processed === 0 && !force) {
    metricsState.windowStart = now;
    return;
  }
  const jobsPerHour = processed ? (processed * 3600000) / Math.max(elapsed, 1) : 0;
  const successRate = processed ? (metricsState.success / processed) * 100 : 0;
  const avgDuration = metricsState.durationCount
    ? metricsState.durationTotal / metricsState.durationCount
    : 0;
  console.log(
    `[metrics] window=${Math.round(elapsed / 1000)}s processed=${processed} success=${successRate.toFixed(
      1
    )}% jobs/hour=${jobsPerHour.toFixed(2)} avg=${Math.round(avgDuration)}ms`
  );
  metricsState.windowStart = now;
  metricsState.processed = 0;
  metricsState.success = 0;
  metricsState.failure = 0;
  metricsState.durationTotal = 0;
  metricsState.durationCount = 0;
}

function installSignalHandlers() {
  const graceful = (signal) => {
    console.log(`[agent] received ${signal}, flushing metrics before exit...`);
    try {
      flushMetrics(true);
    } catch (error) {
      console.warn("[agent] metrics flush error:", error?.message || error);
    }
    process.exit(0);
  };
  process.on("SIGINT", graceful);
  process.on("SIGTERM", graceful);
  process.on("beforeExit", () => flushMetrics(true));
}

installSignalHandlers();

// -----------------------------
// Auto-recovery with health checks
// -----------------------------
let errorCount = 0;
const MAX_CONSECUTIVE_ERRORS = 5;
const HEALTH_CHECK_COOLDOWN = 60000; // 1 minute

async function checkAgentHealth() {
  try {
    const response = await apiGet("/agent/health");
    const text = await response.body.text();

    if (response.statusCode !== 200) {
      console.error(`[agent] Health check failed: ${response.statusCode} ${text}`);
      return false;
    }

    const body = JSON.parse(text);
    console.log("[agent] Health check:", JSON.stringify(body, null, 2));

    if (body?.ok && body?.agent) {
      const { status, activeJobs, recentJobs24h } = body.agent;
      console.log(`[agent] Status: ${status}, Active: ${activeJobs}, Recent 24h: ${recentJobs24h}`);

      if (status === 'healthy') {
        errorCount = 0; // Reset error count if backend says we're healthy
        return true;
      } else if (status === 'degraded') {
        console.warn("[agent] Status degraded - too many active jobs");
        return true; // Continue but with warning
      } else {
        console.error("[agent] Status down - no recent activity");
        return false;
      }
    }
    return false;
  } catch (healthError) {
    console.error("[agent] Health check failed:", healthError?.message || healthError);
    return false;
  }
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
        errorCount++;
        await sleep(Math.min(POLL_MS * 2, 5000));
        continue;
      }

      let job;
      try {
        job = JSON.parse(text);
      } catch {
        console.error(`[agent] invalid JSON from /next: ${text}`);
        errorCount++;
        await sleep(Math.min(POLL_MS * 2, 5000));
        continue;
      }

      // Defensive checks
      if (!job || typeof job !== "object" || !job.jobId) {
        console.error(`[agent] /next returned invalid job payload: ${text}`);
        errorCount++;
        await sleep(Math.min(POLL_MS * 2, 5000));
        continue;
      }

      console.log(`[agent] got job ${job.jobId} profile=${job.profile || "ssh_basic"} target=${job?.target?.address}`);

      const result = await runJob(job);

      const summary = buildSummary(result.findings, result.meta);

      const payload = {
        status: result.status,
        summary,
        findings: result.findings,
        meta: { ...(result.meta || {}), profile: job.profile || "ssh_basic" },
      };
      recordJobMetrics(result.status, result.meta?.durationMs);

      const post = await apiPost(`/infra-scans/${job.jobId}/results`, payload);
      const postText = await post.body.text();

      if (post.statusCode >= 200 && post.statusCode < 300) {
        console.log(`[agent] job ${job.jobId} reported (${result.status})`);
        errorCount = 0; // Reset on success
      } else {
        console.error(`[agent] report failed ${post.statusCode}: ${postText}`);
        errorCount++;
      }
    } catch (err) {
      console.error("[agent] loop error:", err?.stack || err);
      errorCount++;

      // Auto-recovery: After N consecutive errors, run health check
      if (errorCount >= MAX_CONSECUTIVE_ERRORS) {
        console.error(`[agent] ${MAX_CONSECUTIVE_ERRORS} consecutive errors detected, running health check...`);

        const isHealthy = await checkAgentHealth();

        if (!isHealthy) {
          console.error("[agent] Health check failed, waiting before retry...");
          await sleep(HEALTH_CHECK_COOLDOWN);
        }

        // Reset error count after health check attempt
        errorCount = Math.max(0, errorCount - 2); // Reduce but don't fully reset
      } else {
        await sleep(Math.min(POLL_MS * 2, 5000));
      }
    }
  }
}

main();
