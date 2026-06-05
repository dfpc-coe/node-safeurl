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

### v1.0.1 - 2025-06-05

- :bug: Fix types path for built output

### v1.0.0 - 2025-06-04

- :tada: Initial release — SSRF-safe URL validation library
- :tada: `isSafeUrl()` — validates URLs against SSRF attacks (private IPs, blocked protocols, DNS rebinding)
- :tada: `isPrivateIPv4()` / `isPrivateIPv6()` — check if an IP falls in private/special-purpose ranges
- :tada: Uses `@microsoft/antissrf` for maintained block lists
