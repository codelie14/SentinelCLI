# SentinelCLI v1.2 — Référence API REST

> Documentation complète du serveur REST local intégré à SentinelCLI.

---

## Démarrage

```bash
# En mode online uniquement
[sentinel|online]> api start
✓ REST API running at http://127.0.0.1:5000
```

---

## Endpoints

### `GET /`

Index du service — liste tous les endpoints disponibles.

**Réponse :**

```json
{
  "service": "SentinelCLI REST API",
  "version": "1.2.0",
  "endpoints": [
    "/api/status",
    "/api/threats",
    "/api/processes",
    "/api/ports",
    "/api/connections",
    "/api/webhook/test"
  ],
  "timestamp": "2026-02-19T15:00:00"
}
```

---

### `GET /api/status`

État général du service.

```bash
curl http://127.0.0.1:5000/api/status
```

**Réponse :**

```json
{
  "status": "running",
  "mode": "online",
  "timestamp": "2026-02-19T15:00:00"
}
```

---

### `GET /api/threats`

Résultats de la dernière analyse de menaces (après avoir exécuté `threats` dans le shell).

```bash
curl http://127.0.0.1:5000/api/threats
```

**Réponse :**

```json
{
  "security_score": 78,
  "threat_level": "LOW",
  "threats_detected": [],
  "dangerous_ports": [],
  "suspicious_processes": []
}
```

> **Note :** Retourne une erreur si `threats` n'a pas encore été exécuté dans la session.

---

### `GET /api/processes`

Liste des processus en cours (top 50 par mémoire).

```bash
curl http://127.0.0.1:5000/api/processes
```

**Réponse :**

```json
{
  "processes": [
    {
      "pid": 1234,
      "name": "python.exe",
      "cpu_percent": 2.1,
      "memory_percent": 1.8,
      "status": "running",
      "username": "user"
    }
  ],
  "total_count": 87
}
```

---

### `GET /api/ports`

Ports ouverts et services détectés.

```bash
curl http://127.0.0.1:5000/api/ports
```

**Réponse :**

```json
{
  "open_ports": {
    "80": { "service": "HTTP", "address": "0.0.0.0", "type": "LISTEN" },
    "443": { "service": "HTTPS", "address": "0.0.0.0", "type": "LISTEN" }
  },
  "port_count": 12
}
```

---

### `GET /api/connections`

Connexions réseau actives.

```bash
curl http://127.0.0.1:5000/api/connections
```

**Réponse :**

```json
{
  "connections": [
    {
      "local_addr": "192.168.1.100",
      "local_port": 55321,
      "remote_addr": "142.250.74.46",
      "remote_port": 443,
      "status": "ESTABLISHED"
    }
  ]
}
```

---

### `POST /api/webhook/test`

Déclenche un webhook test vers l'URL configurée.

```bash
curl -X POST http://127.0.0.1:5000/api/webhook/test
```

**Réponse :**

```json
{
  "success": true,
  "status_code": 200
}
```

**Payload envoyé au webhook :**

```json
{
  "source": "SentinelCLI",
  "event": "webhook_test",
  "message": "Test webhook from SentinelCLI REST API",
  "timestamp": "2026-02-19T15:00:00"
}
```

---

## Intégration avec un SIEM

### Exemple — Grafana + InfluxDB

```python
import requests
import time

while True:
    r = requests.get("http://127.0.0.1:5000/api/threats")
    data = r.json()
    score = data.get("security_score", 100)
    # Écrire dans InfluxDB ou Prometheus...
    time.sleep(60)
```

### Exemple — Script PowerShell monitoring

```powershell
while ($true) {
    $data = Invoke-RestMethod http://127.0.0.1:5000/api/threats
    Write-Host "Score: $($data.security_score) | Level: $($data.threat_level)"
    Start-Sleep 60
}
```

---

## CORS

L'API autorise les requêtes provenant de `http://localhost:*` pour faciliter l'intégration avec des dashboards web locaux.

```
Access-Control-Allow-Origin: http://localhost:*
Access-Control-Allow-Methods: GET, POST
```

---

## Format Webhook Sortant (Notifications)

Quand SentinelCLI envoie une alerte (Slack/Discord), le payload Discord ressemble à :

```json
{
  "username": "SentinelCLI",
  "embeds": [
    {
      "title": "🔴 SentinelCLI Alert [HIGH]",
      "description": "**Threat Detected**\nScore: 20/100 | Threats: dangerous_port",
      "color": 15204352,
      "footer": { "text": "SentinelCLI v1.2 | 2026-02-19 15:00:00" }
    }
  ]
}
```

### Couleurs par niveau

| Niveau   | Couleur     | Hex       |
| -------- | ----------- | --------- |
| INFO     | Bleu        | `#3498DB` |
| LOW      | Vert        | `#2ECC71` |
| MEDIUM   | Orange      | `#F39C12` |
| HIGH     | Rouge       | `#E74C3C` |
| CRITICAL | Rouge foncé | `#8B0000` |

---

_SentinelCLI v1.2 — Documentation API générée le 2026-02-19_
