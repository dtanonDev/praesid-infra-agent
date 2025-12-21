# praesid-infra-agent

Agent de scan infra (Praesid) qui:
- récupère un job via `GET /api/v1/infra-scans/next`
- exécute des checks réseau (TCP connect, TLS basic, SSH banner)
- renvoie les résultats via `POST /api/v1/infra-scans/:jobId/results`

## Variables d'environnement

- PRAESID_API_BASE (ex: https://praesid.pages.dev/api/v1)
- AGENT_TOKEN (secret)
- AGENT_ID (ex: scanner-oci-1)
- POLL_MS (optionnel, défaut 1500)
- MAX_PORTS (optionnel, défaut 64)
- CONNECT_TIMEOUT_MS (optionnel, défaut 1500)
- OVERALL_TIMEOUT_MS (optionnel, défaut 60000)

## Run (Docker)

```bash
docker build -t praesid-infra-agent:1 .
docker run -d --restart=always \
  --name praesid-infra-agent \
  -e PRAESID_API_BASE="https://praesid.pages.dev/api/v1" \
  -e AGENT_TOKEN="..." \
  -e AGENT_ID="scanner-oci-1" \
  praesid-infra-agent:1
