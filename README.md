# CTI Intelligence Dashboard

A static, self-updating Cyber Threat Intelligence dashboard hosted on GitHub Pages.
Data is fetched from eight sources every 15 minutes via GitHub Actions and committed to this repository.

## Live sources

| Source | Type | API Key |
|--------|------|---------|
| CISA Known Exploited Vulnerabilities | Exploited CVEs | Free |
| Abuse.ch URLhaus | Malware URLs | Free |
| Abuse.ch MalwareBazaar | Malware samples & hashes | Free |
| Abuse.ch ThreatFox | Indicators of Compromise | Free |
| Abuse.ch Feodo Tracker | Botnet C2 IPs | Free |
| NIST NVD CVE | Recent CVEs | Free |
| AlienVault OTX | Threat pulses & campaigns | `OTX_API_KEY` |
| VirusTotal | Multi-engine detections | `VT_API_KEY` |

## Setup

### 1. Create the GitHub repository

```bash
git init
git add .
git commit -m "Initial commit"
gh repo create cti-dashboard --public --source . --push
```

### 2. Enable GitHub Pages

1. Go to **Settings → Pages**
2. Set Source to **Deploy from a branch**
3. Select **main** branch, **/ (root)** folder
4. Click **Save**

Your dashboard will be live at `https://<your-username>.github.io/cti-dashboard/`

### 3. Add optional API keys (for OTX & VirusTotal)

1. Go to **Settings → Secrets and variables → Actions**
2. Click **New repository secret**

| Secret name | Where to get it |
|-------------|----------------|
| `OTX_API_KEY` | [otx.alienvault.com](https://otx.alienvault.com) → My Profile → OTX Key |
| `VT_API_KEY` | [virustotal.com](https://www.virustotal.com) → My API key |

### 4. Trigger the first data fetch

Go to **Actions → Update CTI Data → Run workflow**.
After it completes, refresh your GitHub Pages URL.

From then on, the workflow runs automatically every 15 minutes.
