#!/usr/bin/env python3
"""Checks what x509.create makes with openssl.

Runs tools/make_pki.goose into a temporary directory (the intermediate's
RSA key comes from test/vectors/keys.txt), then has openssl:
verify each leaf (x509_strict, sslserver, host name, explicit policy),
refuse the leaf outside the intermediate's name constraints, verify the
CSR's signature and both CRLs, find the revoked leaf revoked under
-crl_check_all and the others not, and read every private key, whose
public key must be the one in its certificate; the same for the ML-DSA
and DSA hierarchy and the SLH-DSA one (root, leaf, CSR, CRL); and the
rules over a whole path: a CA's key rollover within path length 0 and
another CA beyond it, a server-only leaf under a client-only CA refused
for both purposes and under a server-only one accepted. Go's crypto/x509
(tools/govectors `check`) must verify the ML-DSA leaves and read their
PKCS #8 keys.

    python3 scripts/check_created.py [--goose PATH]
"""

import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def ossl(*a):
    return subprocess.run(["openssl", *a], capture_output=True, text=True)


def main():
    goose = sys.argv[sys.argv.index("--goose") + 1] if "--goose" in sys.argv else \
        os.environ.get("GOOSE") or shutil.which("goose") or os.path.join(ROOT, "..", "goose.git", "build", "goose")
    d = tempfile.mkdtemp()
    key = next(l.split()[2] for l in open(os.path.join(ROOT, "test", "vectors", "keys.txt")) if l.split()[1] == "rsa")
    with open(os.path.join(d, "int.der"), "wb") as f:
        f.write(bytes.fromhex(key))
    p = subprocess.run([goose, os.path.join(ROOT, "tools", "make_pki.goose"), "--", d, os.path.join(d, "int.der")],
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    f = lambda n: os.path.join(d, n)
    results = []

    def expect(label, proc, ok, needle=None):
        good = (proc.returncode == 0) == ok and (needle is None or needle in proc.stdout + proc.stderr)
        results.append(good)
        print(("ok    " if good else "FAIL  ") + label + ("" if good else "\n      " + (proc.stdout + proc.stderr).strip()))

    base = ["verify", "-x509_strict", "-purpose", "sslserver", "-CAfile", f("root.pem"), "-untrusted", f("int.pem")]
    for leaf in ("leaf_ed25519", "leaf_p256", "leaf_p521", "leaf_p224"):
        expect(f"{leaf} verifies", ossl(*base, "-verify_hostname", "api.example.com", f(leaf + ".pem")), True)
        expect(f"{leaf} explicit policy", ossl(*base, "-policy_check", "-explicit_policy", "-policy",
                                               "1.3.6.1.4.1.55555.1", f(leaf + ".pem")), True)
        expect(f"{leaf} other policy refused", ossl(*base, "-policy_check", "-explicit_policy", "-policy",
                                                    "1.3.6.1.4.1.55555.2", f(leaf + ".pem")), False)
        expect(f"{leaf} wrong host refused", ossl(*base, "-verify_hostname", "example.org", f(leaf + ".pem")), False)
        pub_cert = ossl("x509", "-in", f(leaf + ".pem"), "-noout", "-pubkey").stdout
        pub_key = ossl("pkey", "-in", f(leaf + ".key"), "-pubout").stdout
        results.append(pub_cert == pub_key and pub_cert != "")
        print(("ok    " if results[-1] else "FAIL  ") + f"{leaf} key matches certificate")
    expect("leaf under the P-224 intermediate", ossl("verify", "-x509_strict", "-purpose", "sslserver", "-CAfile",
                                                     f("root.pem"), "-untrusted", f("int_p224.pem"),
                                                     "-verify_hostname", "www.example.com", f("leaf_by_p224.pem")), True)
    expect("name constraints enforced", ossl(*base, f("leaf_excluded.pem")), False, "excluded subtree")
    expect("csr signature", ossl("req", "-in", f("csr.pem"), "-verify", "-noout"), True, "verify OK")
    expect("csr san", ossl("req", "-in", f("csr.pem"), "-noout", "-text"), True, "DNS:csr.example.com")
    expect("intermediate crl", ossl("crl", "-in", f("crl_int.pem"), "-CAfile", f("int.pem"), "-noout"), True,
           "verify OK")
    expect("root crl", ossl("crl", "-in", f("crl_root.pem"), "-CAfile", f("root.pem"), "-noout"), True, "verify OK")
    with open(f("crls.pem"), "w") as out:
        out.write(open(f("crl_int.pem")).read() + open(f("crl_root.pem")).read())
    crl = [*base, "-crl_check_all", "-CRLfile", f("crls.pem")]
    expect("revoked leaf", ossl(*crl, f("leaf_ed25519.pem")), False, "revoked")
    expect("unrevoked leaf", ossl(*crl, f("leaf_p256.pem")), True)
    expect("root key parses", ossl("pkey", "-in", f("root.key"), "-noout"), True)
    for leaf, root in (("leaf_mldsa44", "pq_root"), ("leaf_mldsa87", "pq_root"), ("leaf_dsa", "pq_root"),
                       ("leaf_by_dsa", "dsa_root")):
        expect(f"{leaf} verifies", ossl("verify", "-x509_strict", "-purpose", "sslserver", "-CAfile", f(root + ".pem"),
                                        "-verify_hostname", "www.example.com", f(leaf + ".pem")), True)
    for leaf in ("leaf_mldsa44", "leaf_mldsa87", "leaf_dsa"):
        pub_cert = ossl("x509", "-in", f(leaf + ".pem"), "-noout", "-pubkey").stdout
        pub_key = ossl("pkey", "-in", f(leaf + ".key"), "-pubout").stdout
        results.append(pub_cert == pub_key and pub_cert != "")
        print(("ok    " if results[-1] else "FAIL  ") + f"{leaf} key matches certificate")
    expect("ML-DSA leaf under the DSA root refused", ossl("verify", "-CAfile", f("dsa_root.pem"),
                                                          f("leaf_mldsa44.pem")), False)
    expect("ML-DSA csr signature", ossl("req", "-in", f("csr_mldsa.pem"), "-verify", "-noout"), True, "verify OK")
    expect("ML-DSA crl", ossl("crl", "-in", f("crl_pq.pem"), "-CAfile", f("pq_root.pem"), "-noout"), True, "verify OK")
    # SLH-DSA (Go has none, so openssl alone).
    expect("leaf_slhdsa verifies", ossl("verify", "-x509_strict", "-purpose", "sslserver", "-CAfile", f("slh_root.pem"),
                                        "-verify_hostname", "www.example.com", f("leaf_slhdsa.pem")), True)
    pub_cert = ossl("x509", "-in", f("leaf_slhdsa.pem"), "-noout", "-pubkey").stdout
    pub_key = ossl("pkey", "-in", f("leaf_slhdsa.key"), "-pubout").stdout
    results.append(pub_cert == pub_key and pub_cert != "")
    print(("ok    " if results[-1] else "FAIL  ") + "leaf_slhdsa key matches certificate")
    expect("SLH-DSA leaf under the ML-DSA root refused", ossl("verify", "-CAfile", f("pq_root.pem"),
                                                              f("leaf_slhdsa.pem")), False)
    expect("SLH-DSA csr signature", ossl("req", "-in", f("csr_slhdsa.pem"), "-verify", "-noout"), True, "verify OK")
    expect("SLH-DSA crl", ossl("crl", "-in", f("crl_slhdsa.pem"), "-CAfile", f("slh_root.pem"), "-noout"), True,
           "verify OK")
    # The rules over a whole path: a self-issued rollover does not count
    # against path length 0, another CA does; a server-only leaf under a
    # client-only CA is good for neither purpose, under a server-only one
    # for serving.
    with open(f("rollover.pem"), "w") as out:
        out.write(open(f("rollover_old.pem")).read() + open(f("rollover_new.pem")).read())
    with open(f("second_path.pem"), "w") as out:
        out.write(open(f("rollover_old.pem")).read() + open(f("second.pem")).read())
    path = lambda purpose, untrusted, leaf: ossl("verify", "-x509_strict", "-purpose", purpose, "-CAfile", f("root.pem"),
                                                 "-untrusted", f(untrusted), f(leaf))
    expect("rollover within path length 0", path("sslserver", "rollover.pem", "leaf_rollover.pem"), True)
    expect("second CA beyond path length 0", path("sslserver", "second_path.pem", "leaf_second.pem"), False,
           "path length constraint exceeded")
    for purpose in ("sslserver", "sslclient"):
        expect(f"server leaf under a client CA refused as {purpose}", path(purpose, "client_ca.pem", "leaf_disjoint.pem"),
               False, "unsuitable certificate purpose")
    expect("server leaf under a server CA", path("sslserver", "server_ca.pem", "leaf_server_ca.pem"), True)
    # Go's crypto/x509 too, for the ML-DSA certificates (it checks no DSA signatures).
    go = subprocess.run([os.path.join(ROOT, "tools", "govectors.sh"), "check", d], capture_output=True, text=True)
    expect("Go verifies the ML-DSA leaves and reads their keys", go, True, "ok")
    expect("text dump", ossl("x509", "-in", f("int.pem"), "-noout", "-text"), True, "Permitted:")
    shutil.rmtree(d)
    print(f"\n{sum(results)} passed, {len(results) - sum(results)} failed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
