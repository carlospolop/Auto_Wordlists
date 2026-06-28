# Auto_Wordlists

This repo generates practical security wordlists in 3 different ways:
- **`wordlists/trusted_resolvers.txt`** contains DNS resolver IPs that, apparently, can be trusted. It is generated **every 8 hours**.
- **`wordlists/ghdb.json`** contains the Google Hacking Database in JSON format. It is generated **once a week**.
- The **rest** of the files in **`wordlists/`** are web fuzzing, payload, and recon wordlists. They are generated **once a week**.

The recon lists are intentionally tiered instead of merged into one huge file. For example, **`dns_subdomains_standard.txt`** is the fast DNS tier, while HTTP routes, real-world directories, headers, parameters, payloads, and usernames each stay in separate files so tools can choose the right amount of noise for the job.

## Sources

Source URLs, licenses, and preprocessing notes are documented in **`SOURCES.md`**. New sources should add coverage that is not already represented here and should avoid broad aggregators that mostly duplicate existing payloads or add low-signal junk.

## Contribute
The **web fuzzing/discovery** wordlists are generated from custom wordlists located in **`custom_wordlists/`** and from URLs that are indicated in **`scripts/yaml_lists/lists.yaml`**.

Feel free to **submit PRs** with new payloads for the custom lists or new high-signal URLs for the generated wordlists.
