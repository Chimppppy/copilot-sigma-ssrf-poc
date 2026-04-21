# copilot-sigma-ssrf-poc
PoC for unauthenticated SSRF in SOCFortress CoPilot's Sigma download endpoint. POST /api/sigma/download passes caller-supplied URLs verbatim to requests.get() with no auth or allow-list. Zip Slip investigated and confirmed not exploitable on Python 3.11.2. Responsible disclosure.
