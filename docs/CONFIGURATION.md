# SentinelCLI v1.2 — Référence de Configuration

> Toutes les clés de configuration, leurs valeurs par défaut et exemples d'utilisation.

---

## Fichier de configuration

- **Nom :** `sentinel_config.json` (racine du projet)
- **Créé :** automatiquement au premier lancement
- **Ignoré par git :** oui (`.gitignore`)
- **Format :** JSON

### Structure complète

```json
{
  "mode": "offline",
  "api_keys": {
    "virustotal": "",
    "otx": ""
  },
  "notifications": {
    "slack_webhook": "",
    "discord_webhook": "",
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_user": "",
    "smtp_password": "",
    "email_to": ""
  },
  "notifications_threshold": "HIGH",
  "rest_api": {
    "host": "127.0.0.1",
    "port": 5000
  },
  "cloud_backup": {
    "endpoint_url": ""
  },
  "geo_intel": {
    "high_risk_countries": ["CN", "RU", "KP", "IR", "SY", "BY", "CU"]
  }
}
```

---

## Gestion via CLI

```bash
# Afficher toute la configuration (valeurs masquées)
config show

# Lire une valeur
config get virustotal_key

# Définir une valeur
config set <clé> <valeur>
```

---

## Référence complète des clés

### Clés API

| Clé CLI          | Champ JSON            | Description           | Où l'obtenir                                             |
| ---------------- | --------------------- | --------------------- | -------------------------------------------------------- |
| `virustotal_key` | `api_keys.virustotal` | Clé VirusTotal API v3 | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| `otx_key`        | `api_keys.otx`        | Clé AlienVault OTX    | [otx.alienvault.com](https://otx.alienvault.com)         |

---

### Notifications

| Clé CLI            | Champ JSON                      | Description               | Exemple                                          |
| ------------------ | ------------------------------- | ------------------------- | ------------------------------------------------ |
| `slack_webhook`    | `notifications.slack_webhook`   | URL Webhook entrant Slack | `https://hooks.slack.com/services/T.../B.../...` |
| `discord_webhook`  | `notifications.discord_webhook` | URL Webhook Discord       | `https://discord.com/api/webhooks/123/abc`       |
| `smtp_host`        | `notifications.smtp_host`       | Serveur SMTP              | `smtp.gmail.com`                                 |
| `smtp_port`        | `notifications.smtp_port`       | Port SMTP (TLS)           | `587`                                            |
| `smtp_user`        | `notifications.smtp_user`       | Identifiant SMTP          | `user@gmail.com`                                 |
| `smtp_pass`        | `notifications.smtp_password`   | Mot de passe SMTP         | (app password Gmail)                             |
| `email_to`         | `notifications.email_to`        | Adresse de destination    | `admin@company.com`                              |
| `notify_threshold` | `notifications_threshold`       | Seuil minimum d'alerte    | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`      |

#### Niveaux de seuil de notification

```
INFO < LOW < MEDIUM < HIGH < CRITICAL
```

Seules les alertes **≥ seuil** sont envoyées. Exemple avec `notify_threshold = HIGH` :

- ✅ `HIGH` → envoyé
- ✅ `CRITICAL` → envoyé
- ❌ `MEDIUM` → ignoré

---

### REST API

| Clé CLI    | Champ JSON      | Défaut      | Description                                        |
| ---------- | --------------- | ----------- | -------------------------------------------------- |
| `api_host` | `rest_api.host` | `127.0.0.1` | Hôte d'écoute (mettre `0.0.0.0` pour accès réseau) |
| `api_port` | `rest_api.port` | `5000`      | Port TCP                                           |

> ⚠️ **Sécurité :** Ne pas exposer `0.0.0.0` sans protection si vous êtes sur un réseau non-fiable.

---

### Cloud Backup

| Clé CLI          | Champ JSON                  | Description                                                   |
| ---------------- | --------------------------- | ------------------------------------------------------------- |
| `cloud_endpoint` | `cloud_backup.endpoint_url` | URL vers laquelle uploader les rapports (HTTP POST multipart) |

**Format de la requête envoyée :**

```
POST <endpoint>
Content-Type: multipart/form-data

file = <contenu du rapport>
source = "SentinelCLI-v1.2"
timestamp = "2026-02-19T15:00:00"
```

---

### Géo-Intelligence

La liste des codes pays à haut risque peut être modifiée directement dans `sentinel_config.json` :

```json
"geo_intel": {
  "high_risk_countries": ["CN", "RU", "KP", "IR", "SY", "BY", "CU"]
}
```

Codes pays au format **ISO 3166-1 alpha-2** (2 lettres majuscules).

---

## Configuration Gmail SMTP

```bash
# 1. Activer l'authentification à 2 facteurs sur votre compte Google
# 2. Créer un "App Password" sur myaccount.google.com/apppasswords
config set smtp_host smtp.gmail.com
config set smtp_port 587
config set smtp_user votre@gmail.com
config set smtp_pass xxxx-xxxx-xxxx-xxxx
config set email_to destinataire@email.com
```

## Configuration Slack Webhook

```bash
# 1. Créer une App Slack sur api.slack.com/apps
# 2. Activer "Incoming Webhooks"
# 3. Copier l'URL
config set slack_webhook https://hooks.slack.com/services/TXXXXX/BXXXXX/xxxxxxxxxx
```

## Configuration Discord Webhook

```bash
# 1. Paramètres d'un salon Discord → Intégrations → Webhooks
# 2. Créer un Webhook, copier l'URL
config set discord_webhook https://discord.com/api/webhooks/000000/xxxxxxxxxxxxx
```
