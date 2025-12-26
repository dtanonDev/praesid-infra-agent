const envFile = process.env.AGENT_ENV_FILE || ".env.production";

module.exports = {
  apps: [
    {
      name: "praesid-infra-agent",
      script: "./agent.js",
      interpreter: "node",
      instances: 1,
      autorestart: true,
      max_memory_restart: "256M",
      watch: false,
      kill_timeout: 5000,
      env: {
        NODE_ENV: "production",
        AGENT_ENV_FILE: envFile,
      },
      log_date_format: "YYYY-MM-DD HH:mm:ss Z",
    },
  ],
};
