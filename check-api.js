import { request } from "undici";
import "./load-env.js";

const base = (process.env.PRAESID_API_BASE || "").replace(/\/$/, "");
const token = process.env.AGENT_TOKEN;
const agentId = process.env.AGENT_ID || "scanner-1";

if (!base || !token) {
  console.error("Missing PRAESID_API_BASE or AGENT_TOKEN");
  process.exit(1);
}

const endpoint = `${base}/infra-scans/ping`;

async function main() {
  console.log(`[ping] Checking connectivity to ${endpoint}`);
  try {
    const res = await request(endpoint, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        "X-Agent-Id": agentId,
        Accept: "application/json",
      },
    });
    const text = await res.body.text().catch(() => "");
    if (res.statusCode >= 200 && res.statusCode < 400) {
      console.log(`[ping] OK (${res.statusCode})`);
      if (text) console.log(`[ping] Response: ${text}`);
      return;
    }
    console.error(`[ping] Unexpected response ${res.statusCode}: ${text}`);
    process.exitCode = 1;
  } catch (error) {
    console.error("[ping] Connectivity check failed:", error);
    process.exitCode = 1;
  }
}

main();
