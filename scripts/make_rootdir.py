#!/usr/bin/env python3
"""Make test/vectors/rootdir, a certificate directory for test/pool_api.goose
and scripts/check_roots.py, from certificates of vectors/certs.txt:

    roots.pem    root_rsa_other then root_rsa (one name, two keys)
    p384.der     root_p384, DER
    5f2a1c3e.0   a c_rehash-style link to roots.pem (nothing new)
    mixed.crt    root_p384 again as PEM, a CERTIFICATE block that does not
                 parse, and text around them
    readme.txt   no certificate
    sub/ed.pem   root_ed, in a subdirectory, which is not read

    python3 scripts/make_rootdir.py
"""

import base64
import os
import shutil

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def pem(der):
    b = base64.b64encode(der).decode()
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + \
        "\n-----END CERTIFICATE-----\n"


def main():
    certs = {}
    for line in open(os.path.join(ROOT, "test", "vectors", "certs.txt")):
        w = line.split()
        if len(w) == 3 and w[0] == "cert":
            certs[w[1]] = bytes.fromhex(w[2])
    d = os.path.join(ROOT, "test", "vectors", "rootdir")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(os.path.join(d, "sub"))
    with open(os.path.join(d, "roots.pem"), "w") as f:
        f.write(pem(certs["root_rsa_other"]) + pem(certs["root_rsa"]))
    with open(os.path.join(d, "p384.der"), "wb") as f:
        f.write(certs["root_p384"])
    os.symlink("roots.pem", os.path.join(d, "5f2a1c3e.0"))
    with open(os.path.join(d, "mixed.crt"), "w") as f:
        f.write("P-384 root, again\n" + pem(certs["root_p384"]) +
                "-----BEGIN CERTIFICATE-----\nAAECAwQF\n-----END CERTIFICATE-----\ntrailing text\n")
    with open(os.path.join(d, "readme.txt"), "w") as f:
        f.write("Not a certificate.\n")
    with open(os.path.join(d, "sub", "ed.pem"), "w") as f:
        f.write(pem(certs["root_ed"]))


if __name__ == "__main__":
    main()
