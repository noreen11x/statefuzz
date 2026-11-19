"""Download the three public SIP datasets into datasets/raw/.

    python datasets/fetch_datasets.py

  1. ProFuzzBench   the Kamailio seed used by the ProFuzzBench benchmark
  2. RFC 4475       the official SIP "torture test" messages (RFC Editor)
  3. SIPp           scenario files shipped with the SIPp traffic generator

datasets/manifest.json records, for every file: where it came from, when it
was downloaded, its size and its SHA-256 (so anyone can check it is the
original). Needs internet. Standard library only.
"""

import hashlib
import json
import os
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw")

PFB = "https://raw.githubusercontent.com/profuzzbench/profuzzbench/master/subjects/SIP/Kamailio"
SIPP = "https://raw.githubusercontent.com/SIPp/sipp/master/sipp_scenarios"

FILES = [
    ("profuzzbench", "sip-1.raw", f"{PFB}/in-sip/sip-1.raw"),
    ("rfc4475", "rfc4475.txt", "https://www.rfc-editor.org/rfc/rfc4475.txt"),
    ("sipp", "mcd_register.xml", f"{SIPP}/mcd_register.xml"),
    ("sipp", "uc360_register.xml", f"{SIPP}/uc360_register.xml"),
    ("sipp", "uc360_register_challenge.xml", f"{SIPP}/uc360_register_challenge.xml"),
    ("sipp", "pfca_uac.xml", f"{SIPP}/pfca_uac.xml"),
    ("sipp", "pfca_uas.xml", f"{SIPP}/pfca_uas.xml"),
]


def main():
    manifest = []
    for source, name, url in FILES:
        folder = os.path.join(RAW, source)
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, name)
        request = urllib.request.Request(url, headers={"User-Agent": "statefuzz-dataset-fetch"})
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read()
        with open(path, "wb") as f:
            f.write(data)
        manifest.append({"source": source, "file": os.path.relpath(path, HERE), "url": url,
                         "downloaded": time.strftime("%Y-%m-%d %H:%M:%S"),
                         "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        print(f"  {source:<13} {name:<30} {len(data):>7} bytes")
    with open(os.path.join(HERE, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"\n{len(manifest)} files in datasets/raw/, sources listed in datasets/manifest.json")


if __name__ == "__main__":
    main()
