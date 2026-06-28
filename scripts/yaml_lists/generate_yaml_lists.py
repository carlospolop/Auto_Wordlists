from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from pathlib import Path
import os
import re
import tempfile
import unicodedata

import requests
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


CURRENT_DIR = Path(__file__).resolve().parent
CUSTOM_WL_DIR = CURRENT_DIR / ".." / ".." / "custom_wordlists"
FINAL_WL_DIR = CURRENT_DIR / ".." / ".." / "wordlists"
ASSETNOTE_AUTOMATED_INDEX = (
    "https://raw.githubusercontent.com/assetnote/wordlists/master/data/automated.json"
)
ERRORS = []
TIMEOUT = (10, 60)
MAX_WORKERS = int(os.environ.get("AUTO_WORDLISTS_WORKERS", "6"))


class HrefParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name == "href" and value:
                self.hrefs.append(value)


def session_with_retries():
    session = requests.Session()
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
    )
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=MAX_WORKERS,
        pool_maxsize=MAX_WORKERS,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": "Auto_Wordlists/1.0"})
    return session


SESSION = session_with_retries()
ASSETNOTE_CACHE = None


def extract_href(html):
    parser = HrefParser()
    parser.feed(html)
    return parser.hrefs[0] if parser.hrefs else ""


def assetnote_automated_url(prefix):
    global ASSETNOTE_CACHE

    if ASSETNOTE_CACHE is None:
        response = SESSION.get(ASSETNOTE_AUTOMATED_INDEX, timeout=TIMEOUT)
        response.raise_for_status()
        ASSETNOTE_CACHE = response.json().get("data", [])

    candidates = [
        item
        for item in ASSETNOTE_CACHE
        if item.get("Filename", "").startswith(prefix) and item.get("Download")
    ]
    if not candidates:
        raise ValueError(f"No Assetnote automated wordlist found for prefix {prefix!r}")

    latest = max(candidates, key=lambda item: (item.get("Date", 0), item.get("Filename", "")))
    download_url = extract_href(latest["Download"])
    if not download_url:
        raise ValueError(f"Could not extract Assetnote download URL for {latest['Filename']}")
    return download_url


def source_urls(entry):
    urls = [url for url in entry.get("urls", []) if url]
    for source in entry.get("dynamic_urls", []):
        if source.get("type") == "assetnote_automated":
            urls.append(assetnote_automated_url(source["prefix"]))
        else:
            raise ValueError(f"Unsupported dynamic source type: {source.get('type')}")
    return urls


def compile_patterns(patterns):
    return [re.compile(pattern) for pattern in patterns]


def prepare_entry(entry):
    prepared = dict(entry)
    prepared["_allow_patterns"] = compile_patterns(prepared.get("allow_regex", []))
    prepared["_deny_patterns"] = compile_patterns(prepared.get("deny_regex", []))
    prepared["_not_include"] = tuple(prepared.get("not_include", []))
    return prepared


def normalize_line(raw_line, entry):
    line = unicodedata.normalize("NFKC", raw_line).strip()
    if not line:
        return None

    if entry.get("remove_comments") and line.startswith("#"):
        return None

    if entry.get("lowercase"):
        line = line.lower()

    max_length = entry.get("max_length")
    if max_length and len(line) > max_length:
        return None

    min_length = entry.get("min_length")
    if min_length and len(line) < min_length:
        return None

    if any(needle in line for needle in entry["_not_include"]):
        return None

    if entry["_allow_patterns"] and not any(
        pattern.search(line) for pattern in entry["_allow_patterns"]
    ):
        return None

    if any(pattern.search(line) for pattern in entry["_deny_patterns"]):
        return None

    return line


def iter_url_lines(url):
    response = SESSION.get(url, timeout=TIMEOUT, stream=True)
    response.raise_for_status()
    response.encoding = response.encoding or "utf-8"
    for line in response.iter_lines(decode_unicode=True):
        if line is not None:
            yield line


def collect_url(url, entry):
    values = set()

    for raw_line in iter_url_lines(url):
        line = normalize_line(raw_line, entry)
        if line:
            values.add(line)

    return values


def collect_custom_wordlist(wl_name, entry):
    custom_path = CUSTOM_WL_DIR / f"{wl_name}.txt"
    values = set()

    if not custom_path.is_file():
        return values

    with custom_path.open("r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = normalize_line(raw_line, entry)
            if line:
                values.add(line)

    return values


def write_if_changed(path, values):
    content = "\n".join(sorted(values))
    if values:
        content += "\n"

    if path.is_file() and path.read_text(encoding="utf-8", errors="replace") == content:
        return False

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", text=True)
    with os.fdopen(fd, "w", encoding="utf-8") as tmp:
        tmp.write(content)
    os.replace(tmp_name, path)
    return True


def count_lines(path):
    if not path.is_file():
        return 0

    with path.open("r", encoding="utf-8", errors="replace") as f:
        return sum(1 for _ in f)


def build_wordlist(wl_name, entry):
    entry = prepare_entry(entry)
    output_path = FINAL_WL_DIR / f"{wl_name}.txt"
    local_errors = []

    try:
        urls = source_urls(entry)
    except Exception as e:
        ERRORS.append(f"{wl_name}: {e}")
        return wl_name, count_lines(output_path), False, "kept existing after source resolution failure"

    final_list = collect_custom_wordlist(wl_name, entry)

    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, max(len(urls), 1))) as executor:
        future_to_url = {executor.submit(collect_url, url, entry): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                final_list.update(future.result())
            except Exception as e:
                local_errors.append(f"{wl_name} {url}: {e}")

    if local_errors:
        ERRORS.extend(local_errors)
        if output_path.is_file():
            return wl_name, count_lines(output_path), False, "kept existing after source failure"
        return wl_name, len(final_list), False, "not written because source failed"

    changed = write_if_changed(output_path, final_list)
    return wl_name, len(final_list), changed, "updated" if changed else "unchanged"


def main():
    with (CURRENT_DIR / "lists.yaml").open("r", encoding="utf-8") as file:
        yaml_loaded = yaml.safe_load(file)

    summaries = []
    for wl_name, entry in yaml_loaded["lists"].items():
        summaries.append(build_wordlist(wl_name, entry))

    errors_path = CURRENT_DIR / "errors.txt"
    if errors_path.is_file():
        errors_path.unlink()

    if ERRORS:
        errors_path.write_text("\n".join(ERRORS) + "\n", encoding="utf-8")

    for wl_name, count, changed, status in summaries:
        print(f"{wl_name}: {count} lines ({status})")

    if ERRORS:
        print(f"{len(ERRORS)} source(s) failed; see {errors_path}")


if __name__ == "__main__":
    main()
