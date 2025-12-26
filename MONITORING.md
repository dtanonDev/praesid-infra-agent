# Monitoring & Alerting – Praesid Infra Agent

## CloudWatch setup

1. Install the CloudWatch agent on the VM (Amazon Linux: `sudo yum install amazon-cloudwatch-agent`).
2. Copy `cloudwatch-agent.json` to `/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json`.
3. Update the `file_path` entries if your PM2 home differs (`pm2 conf PM2_HOME` to confirm).
4. Start the agent:

```bash
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s
```

### Metrics & dashboards

The config above exposes:

| Metric | Source | Description |
| --- | --- | --- |
| `procstat_cpu_usage` | CloudWatch agent | CPU usage of the Node process |
| `procstat_memory_resident` | CloudWatch agent | RSS memory in bytes |
| `statsd.praesid.jobs_per_hour` | Statsd | Derived from logs (see below) |
| `statsd.praesid.success_rate` | Statsd | Derived from the `recordJobMetrics` logger |

Trigger `statsd` metrics by shipping the `[metrics]` lines through a log forwarder (CloudWatch Logs Insights) or by running a sidecar StatsD collector. The recommended Grafana dashboard tracks:

* Jobs processed / hour (target ≥ 5)
* Success rate (target ≥ 98 %)
* Average job duration
* API latency (derived from PM2 log search)

### Alarms

| Alarm | Threshold | Action |
| --- | --- | --- |
| `PraesidInfraAgent-Down` | No log ingestion for 5 minutes | PagerDuty / Slack |
| `PraesidInfraAgent-HighErrorRate` | `statsd.praesid.success_rate < 90%` during 3 data points | Investigate failing targets |
| `PraesidInfraAgent-CPUHigh` | CPU > 80% for 10 minutes | Scale up VM |

## PM2 health checks

```bash
pm2 status praesid-infra-agent
pm2 logs praesid-infra-agent --lines 200
pm2 resurrect   # reload saved process list
```

## Runbook (incident)

1. `pm2 logs` → identify recurring stack traces.
2. `node check-api.js` → validate API token / connectivity.
3. `curl -H "Authorization: Bearer $AGENT_TOKEN" "$PRAESID_API_BASE/infra-scans/next"` to ensure the backend responds.
4. Restart the agent: `pm2 restart praesid-infra-agent`.
5. If still failing, redeploy via `./pm2-bootstrap.sh .env.production`.

Document troubleshooting steps in Statuspage once resolved.
