# Deployment guide – Praesid Infra Agent

## 1. Pré-requis

- VM Linux (Ubuntu 22.04+ recommandé) avec accès sortant vers `PRAESID_API_BASE`
- Node.js 20 LTS
- `pm2` installé globalement (`npm install -g pm2`)
- Accès SSH avec sudo

## 2. Bootstrap

```bash
git clone git@github.com:praesid/praesid-infra-agent.git /opt/praesid/infra-agent
cd /opt/praesid/infra-agent
cp .env.example .env.production   # éditer les secrets
./pm2-bootstrap.sh .env.production
```

Le script :
- installe les dépendances (`npm install --production`)
- démarre le process via PM2 avec l’environnement indiqué
- exécute `pm2 save` + `pm2 startup` pour garantir le redémarrage automatique

## 3. Fichiers importants

| Fichier | Rôle |
| --- | --- |
| `.env.production` | Secrets (PRAESID_API_BASE, AGENT_TOKEN, AGENT_ID, …) |
| `ecosystem.config.cjs` | Configuration PM2 (+ `AGENT_ENV_FILE`) |
| `cloudwatch-agent.json` | Collecte logs/métriques (optionnel) |
| `check-api.js` | Test ponctuel de connectivité |

## 4. Vérifications

```bash
node check-api.js              # ping API
pm2 status praesid-infra-agent
pm2 logs praesid-infra-agent --lines 200
```

## 5. Monitoring

1. Installer CloudWatch Agent et déployer `cloudwatch-agent.json`.
2. Consommer les lignes `[metrics] …` dans CloudWatch Logs Insights pour jobs/hour & taux de succès.
3. Importer le dashboard Grafana (voir `MONITORING.md`).

## 6. Runbook incident rapide

1. `node check-api.js`
2. `pm2 logs praesid-infra-agent`
3. `pm2 restart praesid-infra-agent`
4. Vérifier l’alarme CloudWatch (`PraesidInfraAgent-Down` / `HighErrorRate`)
5. Escalader si l’erreur API persiste (>15 min)

## 7. Troubleshooting

| Symptôme | Action |
| --- | --- |
| `Missing PRAESID_API_BASE` au démarrage | Vérifier `.env.production` + `AGENT_ENV_FILE` |
| `report failed 401` | Jeton expiré → regénérer dans Praesid |
| Job bloqué > 90s | Ports fermés (firewall), voir findings |
| CPU > 80% | CLI `pm2 monit` puis envisager scaling horizontal |

---

Pour toute modification, mettre à jour la doc + sauvegarder `pm2 save`.
