"""
sort_lists.py  —  Move popular domains to the top of each CSec block list.

Run this after downloading or updating list files:
    python sort_lists.py

The first 500 domains in each file are what CSec loads instantly on startup.
Popular sites (the ones students actually know) go first — obscure ones follow.
"""

import os
import sys

LISTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Lists")

# Most commonly tried sites per category, in priority order.
# Only domains that actually exist in the list file will be moved.
POPULAR = {
    "porn": [
        "pornhub.com", "xvideos.com", "xhamster.com", "xnxx.com",
        "redtube.com", "youporn.com", "tube8.com", "spankbang.com",
        "beeg.com", "eporner.com", "hclips.com", "porntrex.com",
        "sex.com", "brazzers.com", "naughtyamerica.com", "xtube.com",
        "xfantazy.com", "porndig.com", "txxx.com", "hentaigasm.com",
        "rule34.xxx", "e-hentai.org", "nhentai.net", "gelbooru.com",
        "danbooru.donmai.us", "xhamster2.com",
    ],
    "gambling": [
        "bet365.com", "pokerstars.com", "williamhill.com", "betway.com",
        "888casino.com", "casumo.com", "unibet.com", "bwin.com",
        "stoiximan.gr", "betshop.gr", "novibet.gr", "interwetten.gr",
        "pamestoixima.gr", "opap.gr", "betsson.com", "leovegas.com",
        "partypoker.com", "ggpoker.com", "winamax.fr", "pokerstars.eu",
    ],
    "facebook": [
        "facebook.com", "messenger.com", "fb.com", "fbcdn.net",
        "facebook.net", "fb.me", "m.facebook.com",
    ],
    "tiktok": [
        "tiktok.com", "tiktokv.com", "tiktokcdn.com",
        "musical.ly", "ttwstatic.com",
    ],
    "twitter": [
        "twitter.com", "x.com", "twimg.com", "t.co", "api.twitter.com",
    ],
    "ads": [
        "googlesyndication.com", "doubleclick.net", "adnxs.com",
        "advertising.com", "adroll.com", "criteo.com", "outbrain.com",
        "taboola.com", "revcontent.com", "media.net",
        "amazon-adsystem.com", "googleadservices.com",
        "adsrvr.org", "rubiconproject.com", "pubmatic.com",
        "openx.net", "casalemedia.com", "smartadserver.com",
    ],
    "tracking": [
        "google-analytics.com", "googletagmanager.com", "hotjar.com",
        "segment.io", "mixpanel.com", "amplitude.com",
        "mouseflow.com", "fullstory.com", "heap.io",
        "statcounter.com", "newrelic.com", "datadog-browser-agent.com",
        "clarity.ms", "pingdom.net", "logrocket.io",
    ],
    "piracy": [
        "thepiratebay.org", "1337x.to", "rarbg.to",
        "kickasstorrents.to", "torrentz2.eu", "yts.mx",
        "limetorrents.info", "zooqle.com", "nyaa.si",
    ],
    "torrent": [
        "thepiratebay.org", "1337x.to", "rarbg.to",
        "yts.mx", "torrentz2.eu", "kickasstorrents.to",
        "nyaa.si", "limetorrents.info",
    ],
    "crypto": [
        "binance.com", "coinbase.com", "crypto.com", "kraken.com",
        "kucoin.com", "bybit.com", "okx.com", "gate.io",
        "bitcoin.com", "ethereum.org",
    ],
    "drugs": [
        "silkroad.com", "alphabay.com", "hansa.market",
    ],
    "malware": [
        # Malware domains aren't "well known" by name — no useful ordering here.
    ],
    "phishing": [
        # Same — skip sorting these, all entries are equally obscure.
    ],
    "fraud": [],
    "scam": [],
    "ransomware": [],
    "abuse": [],
    "redirect": [],
}


def parse_domain(line):
    s = line.strip()
    if not s or s.startswith('#'):
        return None
    parts = s.split()
    return parts[1].lower() if len(parts) >= 2 else None


def sort_file(path, popular_list):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        raw = f.readlines()

    header = []
    entries = {}   # domain -> original line (preserves order for non-popular)
    order = []     # insertion order for non-popular domains

    for line in raw:
        d = parse_domain(line)
        if d is None:
            header.append(line)
        else:
            if d not in entries:
                entries[d] = line
                order.append(d)

    if not entries:
        print(f"  {os.path.basename(path)}: no domain entries found, skipping")
        return

    popular_set = set(popular_list)
    moved = [d for d in popular_list if d in entries]
    moved_set = set(moved)

    out = list(header)
    for d in moved:
        out.append(entries[d])
    for d in order:
        if d not in moved_set:
            out.append(entries[d])

    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.writelines(out)

    print(f"  {os.path.basename(path)}: {len(entries):,} domains — "
          f"{len(moved)} popular entries moved to top")


def main():
    if not os.path.isdir(LISTS_DIR):
        print(f"Lists folder not found: {LISTS_DIR}")
        sys.exit(1)

    print(f"Sorting block lists in: {LISTS_DIR}\n")

    found_any = False
    for name, popular in POPULAR.items():
        path = os.path.join(LISTS_DIR, f"{name}.txt")
        if not os.path.exists(path):
            continue
        found_any = True
        if not popular:
            print(f"  {name}.txt: no popularity data — left as-is")
            continue
        sort_file(path, popular)

    if not found_any:
        print("No .txt files matched. Check that LISTS_DIR is correct.")
        sys.exit(1)

    print("\nDone. Run again after updating list files.")


if __name__ == "__main__":
    main()
