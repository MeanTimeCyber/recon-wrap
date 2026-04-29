# Overview
A Golang CLI tool to wrap the running of different recon tools from [ProjectDiscovery](https://github.com/projectdiscovery).

# Current Functionality
- Accepts a target domain via `-i` and validates it before running.
- Runs subdomain enumeration with Subfinder and supports optional provider config at `$HOME/.config/subfinder/provider-config.yaml`.
- Filters discovered subdomains with DNSX and keeps only hosts that resolve to at least one live DNS address.
- Performs a two-pass HTTPX scan:
	- Pass 1: broad, faster discovery over common web ports (`Threads: 100`, `RateLimit: 300`).
	- Pass 2: deeper enrichment only for healthy responses (status `2xx/3xx`, plus `401` and `403`) (`Threads: 40`, `RateLimit: 100`).
- Collects and correlates website metadata such as title, server, response details, technologies, CPE, ASN, favicon hashes, protocol indicators, and DNS-related fields.
- Generates a timestamped markdown report per run named like `<domain>_websites-YYYYMMDD-HHMMSS.md` with:
	- a compact summary table,
	- detailed per-site tables for discovered endpoints,
	- root input domain entries highlighted and listed before subdomains.

# Building
Run `Make`.

# Running
Use `go run cli/*.go -i <domain>`, or if you have built it, `recon-wrap -i <domain>`.

Optional flags:
- `-quiet-httpx` disables live URL output while HTTPX is running.

# Links
* https://projectdiscovery.io/blog/do-you-really-know-subfinder-an-in-depth-guide-to-all-features-of-subfinder-beginner-to-advanced#post-installation-instructions
* https://docs.projectdiscovery.io/opensource/httpx/overview
* https://dhiyaneshgeek.github.io/bug/bounty/2020/02/06/recon-with-me/
* https://k3ystr0k3r.medium.com/mastering-subdomain-enumeration-49b6608461da

