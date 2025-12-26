import fs from "node:fs";
import path from "node:path";

const DEFAULT_ENV_FILE = process.env.AGENT_ENV_FILE || ".env";

export function loadAgentEnv(file = DEFAULT_ENV_FILE) {
  if (process.env.AGENT_ENV_LOADED === "1" || process.env.SKIP_AGENT_DOTENV === "1") {
    return;
  }

  try {
    const envPath = path.resolve(process.cwd(), file);
    if (!fs.existsSync(envPath)) {
      return;
    }
    const raw = fs.readFileSync(envPath, "utf8");
    raw.split(/\r?\n/).forEach((line) => {
      if (!line || line.trim().startsWith("#")) return;
      const idx = line.indexOf("=");
      if (idx === -1) return;
      const key = line.slice(0, idx).trim();
      if (!key || process.env[key] !== undefined) return;
      const value = line.slice(idx + 1).trim();
      process.env[key] = value;
    });
    process.env.AGENT_ENV_LOADED = "1";
    console.log(`[agent-env] Loaded environment from ${envPath}`);
  } catch (error) {
    console.warn(`[agent-env] Unable to load ${file}: ${error.message}`);
  }
}

loadAgentEnv();
