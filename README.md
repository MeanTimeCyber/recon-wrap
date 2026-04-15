# Overview
A Golang CLI tool to wrap the running of different recon tools from ProjectDiscovery.

# Current Functionality
- Accepts a target domain via `-i` and validates it before running.
- Runs subdomain enumeration with Subfinder and supports optional provider config at `$HOME/.config/subfinder/provider-config.yaml`.
- Performs a two-pass HTTPX scan:
	- Pass 1: broad, faster discovery over common web ports.
	- Pass 2: deeper enrichment only for healthy responses (status `2xx/3xx`, plus `401` and `403`).
- Collects and correlates website metadata such as title, server, response details, technologies, CPE, ASN, favicon hashes, protocol indicators, and DNS-related fields.
- Generates a timestamped markdown report per run with:
	- a compact summary table,
	- detailed per-site tables for discovered endpoints.


# Building
Run `Make`.

# Running
Use `go run cli/*.go -i <domain>`, or if you have built it, `recon-wrap -i <domain>`.

# Links
* https://projectdiscovery.io/blog/do-you-really-know-subfinder-an-in-depth-guide-to-all-features-of-subfinder-beginner-to-advanced#post-installation-instructions
* https://docs.projectdiscovery.io/opensource/httpx/overview
* https://dhiyaneshgeek.github.io/bug/bounty/2020/02/06/recon-with-me/
* https://k3ystr0k3r.medium.com/mastering-subdomain-enumeration-49b6608461da

