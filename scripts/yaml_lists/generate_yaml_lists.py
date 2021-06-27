import yaml
import os
import requests

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
CUSTOM_WL_DIR = f"{CURRENT_DIR}/../../custom_wordlists"
FINAL_WL_DIR = f"{CURRENT_DIR}/../../wordlists"
ERRORS = []

with open(f"{CURRENT_DIR}/lists.yaml", 'r') as file:
    yaml_loaded = yaml.load(file, Loader=yaml.FullLoader)

for wl_name,entry in yaml_loaded["lists"].items():
    urls = entry["urls"]
    not_includes = entry.get("not_include", [])
    final_list = set()
    for url in urls:
        try:
            if not url:
                continue
            r = requests.get(url)
            for line in r.text.splitlines():
                line = line.strip()
                if not any(ni in line for ni in not_includes) and line:
                    final_list.add(line)
        except Exception as e:
            ERRORS.append(f"{url}: {e}")
    
    if os.path.isfile(f"{CUSTOM_WL_DIR}/{wl_name}.txt"):
        with open(f"{CUSTOM_WL_DIR}/{wl_name}.txt", "r") as f:
            for line in f.readlines():
                line = line.strip()
                if not any(ni in line for ni in not_includes) and line:
                    final_list.add(line)

    with open(f"{FINAL_WL_DIR}/{wl_name}.txt", "w") as f:
        f.write("\n".join(sorted(final_list)))


if os.path.isfile(f"{CURRENT_DIR}/errors.txt"):
    os.remove(f"{CURRENT_DIR}/errors.txt")

if ERRORS:
    with open(f"{CURRENT_DIR}/errors.txt", "w") as f:
            f.write("\n".join(ERRORS))