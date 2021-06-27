# Auto_Wordlists

This repo will generate wordlist in 3 different ways:
- The wordlist **`wordlists/trusted_resolvers.txt`** are the **IPs of DNS servers** that, apparently, can be **trusted**. It's generated **every 8 hours**.
- The wordlist **`wordlists/ghdb.json.txt`** is the google hacking database in JSON format. It's generated **once a week**.
- The **rest** of the wordlists are **web fuzzing/discovery** wordlists. They are generated **once a week**.

## Contribute
The **web fuzzing/discovery** wordlists are generated from custom wordlists located in **`custom_wordlists/`** and from URLs that are indicated in **`scripts/yaml_lists/lists.yaml`**.

Feel free to **submit PRs** with **new payloads for the custom lists or new URLs for the generates wordlists!**
