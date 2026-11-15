#!/usr/bin/env python3
"""Checks what x509.cms signs with openssl: tools/cms_sign.goose signs
"AuthPack, say" with each key of test/vectors/cms.txt by each algorithm;
`openssl cms -verify` must verify each (its signer certificate taken from
the SignedData, trusted as given) and output the content, and must refuse
it with a byte of the signature changed.

    python3 scripts/check_cms.py [--goose PATH]
"""

import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def main():
    goose = sys.argv[sys.argv.index("--goose") + 1] if "--goose" in sys.argv else \
        os.environ.get("GOOSE") or shutil.which("goose") or os.path.join(ROOT, "..", "goose.git", "build", "goose")
    p = subprocess.run([goose, "run", os.path.join(ROOT, "tools", "cms_sign.goose")], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    d = tempfile.mkdtemp()
    bad = 0
    n = 0
    for line in p.stdout.split("\n"):
        if not line.strip():
            continue
        label, h = line.split()
        der = bytes.fromhex(h)
        for changed in (False, True):
            data = bytearray(der)
            if changed:
                data[-3] ^= 0x10
            path = os.path.join(d, "sd.der")
            with open(path, "wb") as f:
                f.write(data)
            v = subprocess.run(["openssl", "cms", "-verify", "-inform", "DER", "-in", path, "-noverify", "-binary"],
                               capture_output=True)
            good = (v.returncode == 0 and v.stdout == b"AuthPack, say") if not changed else v.returncode != 0
            n += 1
            what = label + (" changed, refused" if changed else " verifies")
            print(("ok    " if good else "FAIL  ") + what)
            if not good:
                bad += 1
                print("      " + v.stderr.decode().strip().replace("\n", "\n      "))
    shutil.rmtree(d)
    print(f"{n - bad} passed, {bad} failed")
    sys.exit(1 if bad or n == 0 else 0)


if __name__ == "__main__":
    main()
