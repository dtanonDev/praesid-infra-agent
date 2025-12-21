import { request } from "undici";
import net from "node:net";
import tls from "node:tls";

// -----------------------------
// Config
// -----------------------------
const PRAESID_API_BASE = process.env.PRAESID_API_BASE; // ex: https://infra-queue.dtanon.workers.dev/api/v1
const AGENT_TOKEN = process.env.AGENT_TOKEN;
const AGENT_ID = process.env.AGENT_ID || "scanner-1";

const POLL_MS = parseInt(process.env.POLL_MS || "1500", 10);
const MAX_PORTS = parseInt(process.env.MAX_PORTS || "64", 10);

const DEFAULT_CONNECT_TIMEOUT_MS = parseInt(process.env.CONNECT_TIMEOUT_MS || "1500", 10);
const DEFAULT_OVERALL_TIMEOUT_MS = parseInt(process.env.OVERALL_TIMEOUT_MS || "60000", 10);

if (!PRAESID_API_BASE || !AGENT_TOKEN) {
  console.error("[agent] Missing PRAESID_API_BASE or AGENT_TOKEN");
  process.exit(1);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// -----------------------------
// HTTP helpers
// -----------------------------
async function apiGet(path) {
  const res = await request(`${PRAESID_API_BASE}${path}`, {
    method: "GET",
    headers: {
      "Authorization": `Bearer ${AGENT_TOKEN}`,
      "X-Agent-Id": AGENT_ID,
      "Accept": "application/json",
    },
  });
  return res;
}

async function apiPost(path, body) {
  const res = await request(`${PRAESID_API_BASE}${path}`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${AGENT_TOKEN}`,
      "X-Agent-Id": AGENT_ID,
      "Content-Type": "application/json",
      "Accept": "application/json",
    },
    body: JSON.stringify(body),
  });
  return res;
}

// -----------------------------
// Network checks
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

function tlsBasic(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const started = Date.now();

    const socket = tls.connect({
      host,
      port,
      servername: host, // OK even if host is an IP (cert may mismatch)
      rejectUnauthorized: false,
      timeout: timeoutMs,
    });

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
        },
      });
    });

    socket.on("timeout", () => done("timeout"));
    socket.on("error", (err) => done("error", { error: err.code || err.message }));
  });
}

function sshBanner(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = net.createConnection({ host, port });
    let buf = "";

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

    socket.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      if (buf.includes("\n")) {
        const line = buf.split("\n")[0].trim();
        // SSH banner must start with SSH-
        if (line.startsWith("SSH-")) {
          done("ok", { banner: line });
        } else {
          done("not_ssh", { firstLine: line });
        }
      }
    });

    socket.on("timeout", () => done("timeout"));
    socket.on("error", (err) => done("closed", { error: err.code || err.message }));
  });
}

// -----------------------------
// Findings helpers
// -----------------------------
function finding(category, severity, title, evidence, recommendation) {
  return { category, severity, title, evidence, recommendation };
}

function parsePorts(input) {
  if (Array.isArray(input)) {
    return input
      .map((p) => Number(p))
      .filter((p) => Number.isInteger(p) && p > 0 && p <= 65535)
      .slice(0, MAX_PORTS);
  }
  return [];
}

function isValidSshUsername(user) {
  // Conservative: linux username patterns (avoid spaces/shell)
  // allows: letters, digits, underscore, hyphen, dot; length 1-32
  if (typeof user !== "string") return false;
  if (user.length < 1 || user.length > 32) return false;
  return /^[a-z_][a-z0-9_.-]*$/i.test(user);
}

function normalizePort(val, fallback) {
  const n = Number(val);
  return Number.isInteger(n) && n > 0 && n <= 65535 ? n : fallback;
}

function dateStrToDaysLeft(valid_to) {
  if (!valid_to) return null;
  const ts = Date.parse(valid_to);
  if (!Number.isFinite(ts)) return null;
  return Math.floor((ts - Date.now()) / (1000 * 60 * 60 * 24));
}

// -----------------------------
// Profile runners
// -----------------------------
async function runConnectTest(job) {
  const started = Date.now();
  const target = job.target || {};
  const timeouts = job.timeouts || {};

  const connectMs = Number.isInteger(timeouts.connectMs) ? timeouts.connectMs : DEFAULT_CONNECT_TIMEOUT_MS;

  const host = target.address;
  const sshPort = normalizePort(target.sshPort ?? target.port ?? 22, 22);
  const sshUser = target.sshUser ?? target.user ?? target.username;

  const findings = [];

  // Validate required params
  if (!host) {
    return {
      status: "failed",
      findings: [
        finding("connect_test", "high", "Missing target address", { target }, "Provide a valid IP/hostname."),
      ],
      meta: { durationMs: Date.now() - started, error: "missing_address" },
    };
  }

  if (sshUser && !isValidSshUsername(sshUser)) {
    findings.push(
      finding(
        "connect_test",
        "medium",
        "SSH username format looks unusual",
        { sshUser },
        "This is not blocking for a passive scan, but may be invalid for authenticated audits later."
      )
    );
  }


  // Step 1: TCP connect
  const tcp = await tcpConnect(host, sshPort, Math.max(connectMs, 1000));
  if (tcp.status !== "open") {
    findings.push(
      finding(
        "connect_test",
        "high",
        "SSH port is not reachable",
        { host, port: sshPort, tcpStatus: tcp.status, error: tcp.error || null, rttMs: tcp.rttMs },
        "Check firewall/security list, port number, and that SSH is running."
      )
    );
    return {
      status: "failed",
      findings,
      meta: { durationMs: Date.now() - started, error: "ssh_port_unreachable" },
    };
  }

  // Step 2: SSH banner read
  const banner = await sshBanner(host, sshPort, Math.max(connectMs * 2, 1500));
  if (banner.status === "ok") {
    findings.push(
      finding(
        "connect_test",
        "info",
        "SSH service detected",
        { host, port: sshPort, sshUser, banner: banner.banner, rttMs: banner.rttMs },
        "If you plan to enable authenticated audits later, create a dedicated audit user and install your public key."
      )
    );
    return {
      status: "completed",
      findings,
      meta: { durationMs: Date.now() - started },
    };
  }

  findings.push(
    finding(
      "connect_test",
      "high",
      "Service on port is not SSH",
      { host, port: sshPort, bannerStatus: banner.status, firstLine: banner.firstLine || null, error: banner.error || null },
      "Verify the SSH port. The service responding does not look like SSH."
    )
  );

  return {
    status: "failed",
    findings,
    meta: { durationMs: Date.now() - started, error: "no_ssh_banner" },
  };
}

async function runSshBasic(job) {
  const started = Date.now();

  const target = job.target || {};
  const checks = Array.isArray(job.checks) ? job.checks : [];
  const timeouts = job.timeouts || {};

  const connectMs = Number.isInteger(timeouts.connectMs) ? timeouts.connectMs : DEFAULT_CONNECT_TIMEOUT_MS;
  const overallMs = Number.isInteger(timeouts.overallMs) ? timeouts.overallMs : DEFAULT_OVERALL_TIMEOUT_MS;

  const host = target.address;
  const ports = parsePorts(target.ports);

  if (!host) {
    return {
      status: "failed",
      findings: [
        finding("agent", "high", "Invalid target (missing address)", { target }, "Fix the target address."),
      ],
      meta: { durationMs: Date.now() - started, error: "missing_address" },
    };
  }

  const findings = [];

  // TCP CONNECT
  if (checks.includes("tcp_connect") && ports.length > 0) {
    for (const port of ports) {
      const res = await tcpConnect(host, port, connectMs);
      if (res.status === "open") {
        findings.push(
          finding(
            "ports",
            "info",
            `Port ${port} open`,
            { host, port, rttMs: res.rttMs },
            "Ensure this exposure is intended; restrict by firewall or IP allowlist if possible."
          )
        );
      }
    }
  }

  // TLS BASIC
  if (checks.includes("tls_basic")) {
    const tlsPort = ports.includes(443) ? 443 : (ports[0] || 443);
    const res = await tlsBasic(host, tlsPort, Math.max(connectMs * 2, 2500));

    if (res.status === "ok") {
      const daysLeft = dateStrToDaysLeft(res.cert?.valid_to);

      if (daysLeft !== null && daysLeft < 14) {
        findings.push(
          finding(
            "tls",
            "high",
            "TLS certificate expires soon",
            { host, port: tlsPort, daysLeft, valid_to: res.cert?.valid_to, protocol: res.protocol },
            "Renew/rotate the TLS certificate before expiration."
          )
        );
      } else {
        findings.push(
          finding(
            "tls",
            "info",
            "TLS reachable",
            { host, port: tlsPort, valid_to: res.cert?.valid_to || null, protocol: res.protocol },
            "Keep TLS configuration up to date (protocols/ciphers/certificate rotation)."
          )
        );
      }
    } else {
      findings.push(
        finding(
          "tls",
          "medium",
          "TLS check failed",
          { host, port: tlsPort, ...res },
          "Verify HTTPS is accessible; check firewall rules and TLS configuration."
        )
      );
    }
  }

  // SSH BANNER
  if (checks.includes("ssh_banner")) {
    const sshPort = normalizePort(target.sshPort, ports.includes(22) ? 22 : 22);
    const res = await sshBanner(host, sshPort, Math.max(connectMs * 2, 2500));

    if (res.status === "ok") {
      findings.push(
        finding(
          "ssh",
          "info",
          "SSH service detected",
          { host, port: sshPort, banner: res.banner },
          "Restrict SSH by IP, disable password auth, and prefer modern key algorithms (ed25519)."
        )
      );
    } else if (res.status === "not_ssh") {
      findings.push(
        finding(
          "ssh",
          "high",
          "SSH port responds but does not look like SSH",
          { host, port: sshPort, firstLine: res.firstLine || null },
          "Verify the SSH port; the service responding is not SSH."
        )
      );
    } else {
      findings.push(
        finding(
          "ssh",
          "info",
          "SSH not reachable",
          { host, port: sshPort, ...res },
          "If SSH should be reachable, verify firewall/NAT; otherwise keep it closed."
        )
      );
    }
  }

  const durationMs = Date.now() - started;
  if (durationMs > overallMs) {
    return { status: "failed", findings, meta: { durationMs, error: "overall_timeout" } };
  }

  return { status: "completed", findings, meta: { durationMs } };
}

// -----------------------------
// Job dispatcher (by profile)
// -----------------------------
async function runJob(job) {
  const profile = job?.profile || "ssh_basic";

  if (profile === "connect_test") {
    return await runConnectTest(job);
  }

  // Default: ssh_basic
  return await runSshBasic(job);
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

      console.log(`[agent] got job ${job.jobId} profile=${job.profile || "ssh_basic"} target=${job?.target?.address}`);

      const result = await runJob(job);

      // Keep payload simple; the Worker already knows the job profile in DB.
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
