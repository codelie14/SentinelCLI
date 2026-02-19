# SentinelCLI v1.2 — Guide Complet

> 🛡️ **Cyber Defense Terminal Toolkit** — Outil de surveillance et d'analyse de sécurité en ligne de commande.

---

## Table des Matières

1. [Installation](#1-installation)
2. [Démarrage Rapide](#2-démarrage-rapide)
3. [Système de Modes](#3-système-de-modes)
4. [Commandes Système](#4-commandes-système)
5. [Commandes Réseau](#5-commandes-réseau)
6. [Sécurité & Analyse des Menaces](#6-sécurité--analyse-des-menaces)
7. [Fonctionnalités Offline](#7-fonctionnalités-offline)
8. [Fonctionnalités Online](#8-fonctionnalités-online)
9. [Rapports & Export](#9-rapports--export)
10. [Configuration](#10-configuration)
11. [Architecture des Fichiers](#11-architecture-des-fichiers)

---

## 1. Installation

### Prérequis

- Python **3.10+**
- Windows 10/11 (recommandé) ou Linux
- Droits administrateur recommandés (pour l'audit des tâches planifiées et du registre)

### Installation des dépendances

```bash
pip install -r requirements.txt
```

**Dépendances principales :**

| Package          | Version | Usage                    |
| ---------------- | ------- | ------------------------ |
| `psutil`         | ≥5.9    | Monitoring système       |
| `rich`           | ≥12.0   | Interface terminal       |
| `prompt_toolkit` | ≥3.0    | Shell interactif         |
| `requests`       | ≥2.31   | Fonctionnalités online   |
| `flask`          | ≥3.0    | REST API locale          |
| `cryptography`   | ≥41.0   | Chiffrement des rapports |

### Lancement

```bash
python sentinel.py
```

---

## 2. Démarrage Rapide

```
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
...
🛡️  CYBER DEFENSE TERMINAL TOOLKIT v1.2
Type 'help' for commands | 'mode online/offline' to switch mode

Mode: OFFLINE

[sentinel|offline]>
```

### Première session recommandée

```bash
# 1. Analyse système complète
[sentinel|offline]> sysinfo

# 2. Créer une baseline de référence
[sentinel|offline]> baseline create

# 3. Scanner les menaces
[sentinel|offline]> threats

# 4. Audit de sécurité Windows
[sentinel|offline]> audit

# 5. Exporter un rapport
[sentinel|offline]> export
```

---

## 3. Système de Modes

SentinelCLI v1.2 introduit un **système de modes** pour séparer les fonctionnalités locales des fonctionnalités réseau.

### Modes disponibles

| Mode      | Description                                        | Commandes disponibles                   |
| --------- | -------------------------------------------------- | --------------------------------------- |
| `offline` | Mode par défaut — aucune connexion réseau sortante | Toutes les commandes sauf celles online |
| `online`  | Activer les intégrations cloud et API tierces      | Toutes les commandes                    |

### Changer de mode

```bash
[sentinel|offline]> mode online
✓ Switched to ONLINE mode

[sentinel|online]> mode offline
✓ Switched to OFFLINE mode
```

Le **prompt s'adapte automatiquement** au mode actif : `[sentinel|online]>` vs `[sentinel|offline]>`.

> **Note :** Le mode est persisté dans `sentinel_config.json` — il est conservé entre les sessions.

---

## 4. Commandes Système

### `sysinfo`

Affiche les informations système complètes : OS, CPU, RAM, disques.

```bash
[sentinel|offline]> sysinfo
```

**Données affichées :**

- Système d'exploitation, hostname, architecture
- Usage CPU (physical/logical cores)
- Usage RAM et swap
- Partitions disques avec taux d'utilisation
- Uptime du système

---

### `users`

Liste les sessions utilisateur actives.

```bash
[sentinel|offline]> users
```

---

### `startup`

Affiche les processus les plus consommateurs en mémoire (top 20).

```bash
[sentinel|offline]> startup
```

---

### `watch`

Monitoring temps réel : CPU, RAM, connexions actives. Mise à jour toutes les 2 secondes.

```bash
[sentinel|offline]> watch
# Ctrl+C pour arrêter
```

---

## 5. Commandes Réseau

### `scan [subnet]`

Découverte des hôtes actifs sur le réseau local.

```bash
[sentinel|offline]> scan
[sentinel|offline]> scan 192.168.1.0/24
```

---

### `ports`

Liste tous les ports ouverts et les services associés.

```bash
[sentinel|offline]> ports
```

**Informations affichées :** Port, service identifié, adresse d'écoute, type (TCP/UDP).

---

### `connections`

Analyse toutes les connexions réseau actives. Signale les connexions suspectes.

```bash
[sentinel|offline]> connections
```

---

## 6. Sécurité & Analyse des Menaces

### `threats`

🔴 **Commande principale.** Lance une analyse de sécurité complète multi-couches :

```bash
[sentinel|offline]> threats
```

**Analyse effectuée :**

1. Collecte des informations système
2. Liste et analyse des processus
3. Scan réseau (ports + connexions)
4. Détection d'anomalies (processus, réseau, ressources)
5. Évaluation des vulnérabilités (CVE connus)
6. Calcul du **score de sécurité** `/100`

**Score de sécurité :**

| Score  | Niveau   | Couleur   |
| ------ | -------- | --------- |
| 75–100 | LOW      | 🟢 Vert   |
| 50–74  | MEDIUM   | 🟡 Jaune  |
| 25–49  | HIGH     | 🟠 Orange |
| 0–24   | CRITICAL | 🔴 Rouge  |

> 💡 **Auto-notification :** En mode `online`, si le niveau est `HIGH` ou `CRITICAL`, une alerte est automatiquement envoyée aux canaux configurés (Slack, Discord, Email).

---

### `processes`

Analyse approfondie des processus : ressources élevées + processus suspects.

```bash
[sentinel|offline]> processes
```

---

### `score`

Affiche le dernier score de sécurité calculé avec les recommandations détaillées.

```bash
[sentinel|offline]> score
# Nécessite d'avoir lancé 'threats' au préalable
```

---

## 7. Fonctionnalités Offline

### `baseline`

Crée et compare des snapshots de l'état système pour détecter la **dérive de configuration** (nouveaux processus, ports ouverts, nouveaux utilisateurs, tâches planifiées ajoutées).

```bash
# Créer une baseline de référence
[sentinel|offline]> baseline create

# Comparer l'état actuel à la baseline
[sentinel|offline]> baseline compare

# Voir l'état de la baseline
[sentinel|offline]> baseline
```

**Données capturées :**

- Processus en cours (PID, nom, statut)
- Ports ouverts (port, IP, PID)
- Sessions utilisateur
- Tâches planifiées Windows

**Fichier :** `baselines/baseline.json`

---

### `filescan [path]`

Analyse un répertoire à la recherche de fichiers suspects.

```bash
# Scanner les répertoires utilisateur (Downloads, Desktop, Documents, Temp)
[sentinel|offline]> filescan

# Scanner un répertoire spécifique
[sentinel|offline]> filescan C:\Users\user\Downloads
[sentinel|offline]> filescan C:\Windows\Temp
```

**Détections effectuées :**

| Méthode                  | Description                                                  |
| ------------------------ | ------------------------------------------------------------ |
| Hash MD5/SHA256          | Comparaison avec base de hachages malveillants connus        |
| Extensions suspectes     | `.exe`, `.bat`, `.ps1`, `.vbs`, `.hta`, `.jar`, etc.         |
| Fichiers cachés          | Attribut `Hidden` ou `System` sur Windows                    |
| Emplacements inhabituels | Exécutables dans `%TEMP%`, `%APPDATA%`, dossiers navigateurs |

---

### `audit`

Audit de sécurité Windows complet : détecte les persistances malveillantes courantes.

```bash
[sentinel|offline]> audit
```

**Vérifications effectuées :**

| Catégorie            | Description                                          | Risques détectés                               |
| -------------------- | ---------------------------------------------------- | ---------------------------------------------- |
| Tâches planifiées    | Toutes les tâches + analysis des commandes exécutées | Scripts PowerShell, rundll32, chemins suspects |
| Clés de registre Run | `HKLM\Run`, `HKCU\Run` et variantes                  | Persistances malware                           |
| Partages réseau      | Ouverture de partages Windows                        | Partages non-standard                          |

**Niveaux de risque :** `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`

---

### `timeline [heures|start|stop|clear]`

Enregistrement forensique en temps réel des événements système (thread background).

```bash
# Démarrer la surveillance
[sentinel|offline]> timeline start

# Voir les événements des dernières 24h
[sentinel|offline]> timeline
[sentinel|offline]> timeline 48

# Arrêter la surveillance
[sentinel|offline]> timeline stop

# Effacer la timeline
[sentinel|offline]> timeline clear
```

**Événements enregistrés :**

- Démarrage/arrêt de processus
- Ouverture/fermeture de ports en écoute

**Fichier :** `logs/timeline.json`

---

### `snapshot`

Gestionnaire de snapshots point-dans-le-temps pour comparer l'évolution du système.

```bash
# Prendre un snapshot
[sentinel|offline]> snapshot take
[sentinel|offline]> snapshot take "avant-install-logiciel"

# Lister tous les snapshots
[sentinel|offline]> snapshot list

# Comparer deux snapshots
[sentinel|offline]> snapshot diff <id1> <id2>

# Supprimer un snapshot
[sentinel|offline]> snapshot delete <id>
```

**Données d'un snapshot :**

- Liste des processus (PID, nom, CPU%, RAM%)
- Ports ouverts
- Usage CPU et RAM moyens

**Dossier :** `snapshots/`

---

## 8. Fonctionnalités Online

> **Prérequis :** passer en mode online avec `mode online`

### `vtcheck [hash]`

Vérification de hachages de fichiers contre la base VirusTotal (70+ moteurs antivirus).

```bash
# Vérifier un hash spécifique
[sentinel|online]> vtcheck d41d8cd98f00b204e9800998ecf8427e

# Scanner les processus en cours d'exécution (max 10 — limite API gratuite)
[sentinel|online]> vtcheck
```

**Résultat affiché :**

- Verdict : `CLEAN` / `SUSPICIOUS` / `MALICIOUS`
- Ratio de détection : ex. `3/72 engines`
- Nom du fichier identifié

**Configuration requise :**

```bash
[sentinel|online]> config set virustotal_key VOTRE_CLE_API
```

> **API gratuite VirusTotal :** 4 lookups/minute, 500/jour. Obtenez une clé sur [virustotal.com](https://www.virustotal.com/gui/join-us)

---

### `intel`

Intégration AlienVault OTX — feeds de renseignement sur les menaces.

```bash
# Télécharger les derniers pulses OTX (IOCs: IPs, domaines)
[sentinel|online]> intel fetch

# Scanner les connexions actives contre la base IOC chargée
[sentinel|online]> intel scan
```

**Workflow recommandé :**

```bash
intel fetch   # Charge les IOCs en mémoire
intel scan    # Compare les IPs actives aux IOCs
```

**Configuration requise :**

```bash
[sentinel|online]> config set otx_key VOTRE_CLE_OTX
```

> Clé gratuite sur [otx.alienvault.com](https://otx.alienvault.com)

---

### `geoip [ip]`

Géolocalisation des connexions réseau actives. Identifie les pays à haut risque.

```bash
# Géolocaliser une IP spécifique
[sentinel|online]> geoip 8.8.8.8

# Analyser toutes les connexions actives
[sentinel|online]> geoip
```

**Pays à haut risque par défaut :** CN, RU, KP, IR, SY, BY, CU

> 💡 **Aucune clé API requise** — utilise [ip-api.com](http://ip-api.com) (gratuit, 3000 req/h)

---

### `notify`

Envoyer des alertes via Slack, Discord, et Email.

```bash
# Tester tous les canaux configurés
[sentinel|online]> notify test

# Envoyer une alerte manuelle
[sentinel|online]> notify info "Scan de sécurité démarré"
[sentinel|online]> notify high "Connexion suspecte détectée sur port 4444"
[sentinel|online]> notify critical "Processus malveillant identifié"
```

**Niveaux disponibles :** `info` / `low` / `medium` / `high` / `critical`

**Configuration :**

```bash
config set slack_webhook https://hooks.slack.com/services/...
config set discord_webhook https://discord.com/api/webhooks/...
config set smtp_host smtp.gmail.com
config set smtp_user votre@email.com
config set smtp_pass votre_mot_de_passe
config set email_to destinataire@email.com
config set notify_threshold HIGH   # Seuil minimum pour les alertes
```

---

### `api`

Serveur REST local Flask exposant les données SentinelCLI pour intégration avec des outils tiers (SIEM, dashboards, scripts).

```bash
# Démarrer l'API (port 5000 par défaut)
[sentinel|online]> api start

# Vérifier l'état
[sentinel|online]> api

# Arrêter
[sentinel|online]> api stop
```

**Endpoints disponibles :**

| Méthode | Endpoint            | Description                  |
| ------- | ------------------- | ---------------------------- |
| `GET`   | `/`                 | Index + liste des endpoints  |
| `GET`   | `/api/status`       | État du service              |
| `GET`   | `/api/threats`      | Dernière analyse des menaces |
| `GET`   | `/api/processes`    | Processus en cours           |
| `GET`   | `/api/ports`        | Ports ouverts                |
| `GET`   | `/api/connections`  | Connexions actives           |
| `POST`  | `/api/webhook/test` | Déclencher un webhook test   |

**Exemple d'utilisation :**

```bash
curl http://127.0.0.1:5000/api/threats
curl http://127.0.0.1:5000/api/processes
```

**Configuration du port :**

```bash
config set api_port 8080
```

---

### `backup [filepath]`

Upload des rapports vers un endpoint cloud (HTTP/S3) configuré.

```bash
# Uploader un rapport spécifique
[sentinel|online]> backup reports/SentinelCLI_Report_20260219.md

# Uploader tous les rapports du dossier reports/
[sentinel|online]> backup
```

**Configuration :**

```bash
config set cloud_endpoint https://votre-serveur.com/upload
```

---

## 9. Rapports & Export

### `export`

Génère un rapport Markdown complet dans `reports/`.

```bash
# Rapport standard
[sentinel|offline]> export

# Rapport chiffré AES-256 (mot de passe requis)
[sentinel|offline]> export --encrypt
```

**Format du fichier :** `reports/SentinelCLI_Report_YYYYMMDD_HHMMSS.md`

**Sections du rapport :**

- Résumé exécutif (score, niveau de menace)
- Informations système
- Analyse réseau
- Évaluation des vulnérabilités
- Détection d'anomalies
- Recommandations

### Rapport chiffré (`--encrypt`)

```bash
[sentinel|offline]> export --encrypt
Encryption password: ****
✓ Encrypted report: reports/SentinelCLI_Report_20260219.md.enc
  Salt is prepended to the file (first 16 bytes)
```

**Algorithme :** AES-256 via PBKDF2-HMAC-SHA256 (480 000 itérations)

**Déchiffrement Python :**

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

with open("report.md.enc", "rb") as f:
    data = f.read()

salt = data[:16]
encrypted = data[16:]
password = b"votre_mot_de_passe"

kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
key = base64.urlsafe_b64encode(kdf.derive(password))
decrypted = Fernet(key).decrypt(encrypted)
print(decrypted.decode())
```

---

## 10. Configuration

### Voir la configuration

```bash
[sentinel|offline]> config show
```

### Modifier un paramètre

```bash
[sentinel|offline]> config set <clé> <valeur>
```

### Référence des clés

| Clé                | Description              | Exemple                                                           |
| ------------------ | ------------------------ | ----------------------------------------------------------------- |
| `virustotal_key`   | Clé API VirusTotal       | `config set virustotal_key ABC123`                                |
| `otx_key`          | Clé API AlienVault OTX   | `config set otx_key DEF456`                                       |
| `slack_webhook`    | URL Webhook Slack        | `config set slack_webhook https://hooks.slack.com/...`            |
| `discord_webhook`  | URL Webhook Discord      | `config set discord_webhook https://discord.com/api/webhooks/...` |
| `smtp_host`        | Serveur SMTP             | `config set smtp_host smtp.gmail.com`                             |
| `smtp_port`        | Port SMTP                | `config set smtp_port 587`                                        |
| `smtp_user`        | Identifiant SMTP         | `config set smtp_user user@gmail.com`                             |
| `smtp_pass`        | Mot de passe SMTP        | `config set smtp_pass secret`                                     |
| `email_to`         | Destinataire des alertes | `config set email_to admin@company.com`                           |
| `api_host`         | Hôte REST API            | `config set api_host 0.0.0.0`                                     |
| `api_port`         | Port REST API            | `config set api_port 5000`                                        |
| `cloud_endpoint`   | URL d'upload cloud       | `config set cloud_endpoint https://...`                           |
| `notify_threshold` | Seuil de notification    | `config set notify_threshold MEDIUM`                              |

**Fichier de configuration :** `sentinel_config.json` (racine du projet, ignoré par git)

---

## 11. Architecture des Fichiers

```
SentinelCLI/
│
├── sentinel.py                    # Point d'entrée principal
├── config.py                      # Gestion de la configuration
├── requirements.txt               # Dépendances Python
├── sentinel_config.json           # Config persistée (créée au 1er lancement)
│
├── commands/                      # Groupes de commandes
│   ├── __init__.py
│   ├── config_commands.py         # mode, config
│   ├── offline_commands.py        # baseline, filescan, audit, timeline, snapshot
│   └── online_commands.py         # vtcheck, intel, geoip, notify, api, backup
│
├── engine/                        # Moteurs d'analyse
│   ├── __init__.py
│   ├── system_monitor.py          # Infos système (CPU, RAM, disk)
│   ├── network_monitor.py         # Ports, connexions
│   ├── threat_engine.py           # Score de sécurité
│   ├── anomaly_detector.py        # Détection d'anomalies
│   ├── advanced_port_scanner.py   # Base de données de ports
│   ├── vulnerability_assessment.py # CVEs connus
│   ├── alert_system.py            # Journalisation et alertes
│   ├── baseline_manager.py        # Baseline système ← v1.2
│   ├── file_scanner.py            # Analyse de fichiers ← v1.2
│   ├── windows_audit.py           # Audit Windows ← v1.2
│   ├── forensic_timeline.py       # Timeline forensique ← v1.2
│   ├── snapshot_manager.py        # Snapshots ← v1.2
│   └── online/                    # Intégrations cloud ← v1.2
│       ├── __init__.py
│       ├── virustotal.py          # API VirusTotal v3
│       ├── threat_intel.py        # AlienVault OTX
│       ├── geo_intel.py           # Géolocalisation IP
│       ├── notifier.py            # Slack / Discord / Email
│       ├── rest_api.py            # Serveur Flask REST
│       └── cloud_backup.py        # Upload cloud
│
├── modules/                       # Modules applicatifs
│   ├── network_scanner.py         # Découverte réseau
│   ├── process_analyzer.py        # Analyse processus
│   └── report_generator.py        # Génération de rapports
│
├── baselines/                     # Baselines sauvegardées (git-ignored)
├── snapshots/                     # Snapshots sauvegardés
├── reports/                       # Rapports générés (git-ignored)
├── logs/                          # Logs et timeline (git-ignored)
│   ├── command_history.txt        # Historique des commandes
│   ├── timeline.json              # Timeline forensique
│   └── events.jsonl               # Événements structurés
│
└── docs/                          # Documentation
    ├── GUIDE.md                   # Ce fichier
    ├── CONFIGURATION.md           # Référence complète de configuration
    └── API_REFERENCE.md           # Documentation de l'API REST
```

---

## Raccourcis & Conseils

| Touche    | Action                                   |
| --------- | ---------------------------------------- |
| `↑` / `↓` | Naviguer dans l'historique des commandes |
| `Tab`     | Auto-complétion des commandes            |
| `Ctrl+C`  | Interrompre une opération en cours       |
| `Ctrl+D`  | Quitter SentinelCLI                      |

### Workflow de sécurité recommandé (quotidien)

```bash
# Matin
baseline compare           # Vérifier les changements depuis hier
threats                    # Analyse complète
audit                      # Audit Windows (si sur Windows)

# Si online
intel fetch                # MAJ du feed de menaces
geoip                     # Vérifier les connexions géographiques
vtcheck                   # Vérifier les processus

# Export
export                     # Rapport journalier
```

---

_SentinelCLI v1.2 — Documentation générée le 2026-02-19_
