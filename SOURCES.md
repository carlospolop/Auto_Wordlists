# Sources

Generated web fuzzing, payload, and recon lists are declared in `scripts/yaml_lists/lists.yaml`.
The generator normalizes UTF-8/LF output, removes duplicates, and applies per-list filters where a source is known to contain comments, symbols, full URLs, overlong artifacts, or other low-signal entries.

## Recon and Discovery

| Output | Source | Upstream license | Preprocessing |
| --- | --- | --- | --- |
| `dns_subdomains_standard.txt` | SecLists `Discovery/DNS/subdomains-top1million-110000.txt` | MIT | Lowercase, comments removed, DNS-label regex, max 63 chars |
| `http_api_routes_core.txt` | SecLists `Discovery/Web-Content/api/api-endpoints-res.txt` | MIT | Lowercase, comments removed, programming operators and whitespace removed |
| `http_api_routes_realworld.txt` | Assetnote latest `httparchive_apiroutes_*` from `data/automated.json` | Apache-2.0 | Lowercase, comments removed, full URLs, query strings, fragments, and whitespace removed |
| `http_dirs_realworld.txt` | Assetnote latest `httparchive_directories_1m_*` from `data/automated.json` | Apache-2.0 | Lowercase, comments removed, full URLs, query strings, fragments, whitespace, and punctuation-only paths removed |
| `http_headers_hidden.txt` | PortSwigger Param Miner `resources/headers` | Apache-2.0 | Lowercase, comments removed, HTTP-header-name regex |
| `http_params_realworld.txt` | Assetnote latest `httparchive_parameters_top_1m_*` from `data/automated.json` | Apache-2.0 | Lowercase, comments removed, parameter-name regex, placeholders, one-character junk, and URL artifacts removed |
| `usernames_default.txt` | SecLists `Usernames/cirt-default-usernames.txt` | MIT | Lowercase, comments and whitespace removed |
| `bf_directories.txt` | SecLists `raft-large-directories.txt`, SecLists `DirBuster-2007_directory-list-2.3-medium.txt`, dirsearch `db/dicc.txt` | MIT / GPL-2.0-or-later for dirsearch | Exact-line dedupe |

## Payloads

| Output | Source families | Upstream license notes | Preprocessing |
| --- | --- | --- | --- |
| `command_injection.txt` | SecLists and IntruderPayloads | MIT and source-specific project license | Exact-line dedupe plus custom entries |
| `file_inclusion_linux.txt` | SecLists and IntruderPayloads | MIT and source-specific project license | Exact-line dedupe, Windows drive-letter strings excluded |
| `file_inclusion_windows.txt` | SecLists, windowsblindread, PayloadsAllTheThings | MIT and source-specific project licenses | Exact-line dedupe plus custom entries |
| `sqli.txt` | IntruderPayloads, SecLists, PayloadsAllTheThings | Mixed permissive/source-specific project licenses | Exact-line dedupe |
| `ssi_esi.txt` | IntruderPayloads and SecLists | MIT and source-specific project license | Exact-line dedupe plus custom entries |
| `ssti.txt` | PayloadsAllTheThings and SecLists | Mixed permissive/source-specific project licenses | Exact-line dedupe plus custom entries |
| `xss.txt` | IntruderPayloads, SecLists, PayloadsAllTheThings | Mixed permissive/source-specific project licenses | Exact-line dedupe plus custom entries |
| `xss_polyglots.txt` | PayloadsAllTheThings and SecLists | MIT and source-specific project licenses | Exact-line dedupe plus custom entries |
| `xss_portswigger.txt` | SecLists `XSS-Cheat-Sheet-PortSwigger.txt` | MIT | Exact-line dedupe |
| `xxe.txt` | SecLists, PayloadsAllTheThings, IntruderPayloads | Mixed permissive/source-specific project licenses | Exact-line dedupe |
| `crlf.txt`, `dangling_markup.txt`, `redos.txt`, `xslt.txt` | Local `custom_wordlists/` files | Project-local content | Exact-line dedupe |

## Other Generated Files

| Output | Source | Notes |
| --- | --- | --- |
| `trusted_resolvers.txt` | Resolver generation workflow | Generated every 8 hours |
| `ghdb.json` | Google Hacking Database scraper | Generated weekly |

## Source Selection Rules

Prefer primary or well-maintained project sources with clear methodology and licensing. Keep fast/default and broad/thorough tiers separate. Do not merge unrelated use cases into a single mega-list, and avoid adding new payload aggregators unless they provide clearly unique coverage.
