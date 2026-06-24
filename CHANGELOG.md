# CHANGELOG

## Emoji Cheatsheet
- :pencil2: doc updates
- :bug: when fixing a bug
- :rocket: when making general improvements
- :white_check_mark: when adding tests
- :arrow_up: when upgrading dependencies
- :tada: when adding new features

## Version History

### Pending Fixed

### v1.5.0 - 2026-06-24

- :rocket: Resolve DNS names of allow list if blocked by SSRF checks, allowing them to bypass the checks

### v1.4.0 - 2026-06-06

- :rocket: Add verbose option to type response

### v1.3.0 - 2026-06-06

- :rocket: Add allow list to allow specific URLs or IPs to bypass SSRF checks

### v1.2.0 - 2026-06-06

- :rocket: Expose a `fetch` wrapper that integrates `isSafeUrl()` checks to prevent SSRF vulnerabilities in HTTP requests

### v1.1.0 - 2026-06-06

- :rocket: Implement Type Safe fetch wrapper to prevent SSRF vulnerabilities in HTTP requests

### v1.0.1 - 2025-06-05

- :bug: Fix types path for built output

### v1.0.0 - 2025-06-04

- :tada: Initial release — SSRF-safe URL validation library
- :tada: `isSafeUrl()` — validates URLs against SSRF attacks (private IPs, blocked protocols, DNS rebinding)
- :tada: `isPrivateIPv4()` / `isPrivateIPv6()` — check if an IP falls in private/special-purpose ranges
- :tada: Uses `@microsoft/antissrf` for maintained block lists
