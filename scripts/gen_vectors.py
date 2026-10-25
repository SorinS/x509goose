#!/usr/bin/env python3
"""Make the x509 test vectors with openssl.

test/vectors/certs.txt: a small PKI built with openssl, covering each
signature algorithm the package verifies (RSA PKCS #1 v1.5 with SHA-256,
384 and 512, RSA-PSS, ECDSA on P-256 and P-384, Ed25519) and one
certificate for each way a path can fail. Per certificate:

    cert <name> <hex DER>
    subject|issuer <name> <RFC 4514 text, from openssl -nameopt RFC2253>
    serial <name> <hex>
    dates <name> <notBefore> <notAfter>          (seconds since 1970)
    dns <name> <dNSName>...                       ip <name> <hex>...
    ca <name> <0|1> <pathLen or -1>

then the path cases, each also run through `openssl verify` (which must
agree on pass or fail):

    case <label> <leaf> <intermediates,...|-> <roots,...> <now> <host|-> <expected error>

test/vectors/roots.pem and roots.txt: the system's root store
(/etc/ssl/cert.pem) with openssl's subject for each, and whether its
self-signature is one this package can check.

    python3 scripts/gen_vectors.py
"""

import calendar
import os
import re
import shutil
import subprocess
import tempfile
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
NOW = 1793000000           # 2026-10-26, fixed so the vectors never change meaning
DAY = 86400

ERR = {"ok": 0, "malformed": 1, "unsupported": 2, "bad_signature": 3, "expired": 4,
       "not_yet_valid": 5, "unknown_issuer": 6, "not_ca": 7, "path_length": 8,
       "key_usage": 9, "eku": 10, "hostname": 11, "critical": 12}


def ossl(*args, input=None, check=True):
    p = subprocess.run(["openssl", *args], input=input, capture_output=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args)}: {p.stderr.decode()}")
    return p


def gtime(t):
    return time.strftime("%Y%m%d%H%M%SZ", time.gmtime(t))


class PKI:
    def __init__(self, tmp):
        self.tmp = tmp
        self.der = {}

    def path(self, n):
        return os.path.join(self.tmp, n)

    def key(self, name, kind):
        args = {"rsa": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
                "p256": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
                "p384": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"],
                "ed25519": ["-algorithm", "ED25519"]}[kind]
        ossl("genpkey", *args, "-out", self.path(f"{name}.key"))

    def cert(self, name, kind, subject, issuer=None, ext="", digest="sha256", pss=False,
             start=NOW - 30 * DAY, end=NOW + 3650 * DAY):
        """Makes name.pem, signed by issuer (itself when None)."""
        self.key(name, kind)
        with open(self.path(f"{name}.ext"), "w") as f:
            f.write(ext.replace(";", "\n") + "\n")
        ossl("req", "-new", "-key", self.path(f"{name}.key"), "-subj", subject,
             "-out", self.path(f"{name}.csr"))
        signer = issuer or name
        sign = ["-CA", self.path(f"{issuer}.pem"), "-CAkey", self.path(f"{issuer}.key")] if issuer \
            else ["-key", self.path(f"{name}.key")]
        opts = []
        if kind != "ed25519" and not self.is_ed(signer):
            opts += [f"-{digest}"]
        if pss:
            opts += ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:digest"]
        ossl("x509", "-req", "-in", self.path(f"{name}.csr"), *sign, *opts,
             "-not_before", gtime(start), "-not_after", gtime(end),
             "-set_serial", str(0x1000 + len(self.der)), "-extfile", self.path(f"{name}.ext"),
             "-out", self.path(f"{name}.pem"))
        self.der[name] = ossl("x509", "-in", self.path(f"{name}.pem"), "-outform", "DER").stdout
        self.kind = getattr(self, "kind", {})
        self.kind[name] = kind

    def is_ed(self, name):
        return getattr(self, "kind", {}).get(name) == "ed25519"


CA = "basicConstraints=critical,CA:TRUE;keyUsage=critical,keyCertSign,cRLSign"
LEAF = ("basicConstraints=critical,CA:FALSE;keyUsage=critical,digitalSignature;"
        "extendedKeyUsage=serverAuth;subjectAltName=DNS:example.com,DNS:*.example.com,IP:192.0.2.1")


def fields(pki, name):
    pem = pki.path(f"{name}.pem")
    out = ossl("x509", "-in", pem, "-noout", "-subject", "-issuer", "-serial", "-startdate",
               "-enddate", "-nameopt", "RFC2253,-esc_msb").stdout.decode()
    v = dict(line.split("=", 1) for line in out.splitlines())
    lines = [f"cert {name} {pki.der[name].hex()}",
             f"subject {name} {v['subject'] or '-'}", f"issuer {name} {v['issuer']}",
             f"serial {name} {v['serial']}"]
    def ts(s):
        return calendar.timegm(time.strptime(s.replace(" GMT", ""), "%b %d %H:%M:%S %Y"))
    lines.append(f"dates {name} {ts(v['notBefore'])} {ts(v['notAfter'])}")
    text = ossl("x509", "-in", pem, "-noout", "-ext", "subjectAltName,basicConstraints",
                check=False).stdout.decode()
    dns = re.findall(r"DNS:([^,\s]+)", text)
    ips = ["".join(f"{int(x):02x}" for x in ip.split(".")) for ip in re.findall(r"IP Address:([0-9.]+)", text)]
    lines.append(f"dns {name} {' '.join(dns) or '-'}")
    lines.append(f"ip {name} {' '.join(ips) or '-'}")
    ca = "CA:TRUE" in text
    pl = re.search(r"pathlen:(\d+)", text)
    lines.append(f"ca {name} {int(ca)} {pl.group(1) if pl else -1}")
    return lines


def main():
    lines, cases = [], []
    with tempfile.TemporaryDirectory() as tmp:
        k = PKI(tmp)
        k.cert("root_rsa", "rsa", "/C=US/O=Goose Test/CN=Goose Root R1", ext=CA)
        k.cert("root_p384", "p384", "/C=US/O=Goose Test/CN=Goose Root E1", ext=CA, digest="sha384")
        k.cert("root_ed", "ed25519", "/O=Goose Test/CN=Goose Root Ed", ext=CA)
        k.cert("int_ec", "p384", "/O=Goose Test/CN=Goose Issuing E1", "root_rsa",
               CA + ";basicConstraints=critical,CA:TRUE,pathlen:0".replace("basicConstraints=critical,CA:TRUE;", ""),
               digest="sha384")
        k.cert("int_pss", "rsa", "/O=Goose Test/CN=Goose Issuing PSS", "root_rsa",
               "basicConstraints=critical,CA:TRUE;keyUsage=critical,keyCertSign", pss=True)
        k.cert("int_noca", "p256", "/O=Goose Test/CN=Not A CA", "root_rsa",
               "basicConstraints=critical,CA:FALSE;keyUsage=critical,keyCertSign")
        k.cert("int_noku", "p256", "/O=Goose Test/CN=CA Without keyCertSign", "root_rsa",
               "basicConstraints=critical,CA:TRUE;keyUsage=critical,digitalSignature")
        k.cert("int_client", "p256", "/O=Goose Test/CN=Client Only CA", "root_rsa",
               CA + ";extendedKeyUsage=clientAuth")
        k.cert("int_sub", "p256", "/O=Goose Test/CN=Below Pathlen Zero", "int_ec", CA, digest="sha384")
        k.cert("leaf_ec", "p256", "/CN=example.com", "int_ec", LEAF, digest="sha384")
        k.cert("leaf_pss", "rsa", "/C=US/O=Ex\\, Inc./CN=example.com", "int_pss", LEAF,
               digest="sha512", pss=True)
        k.cert("leaf_ed", "ed25519", "/CN=example.com", "root_ed", LEAF)
        k.cert("leaf_p384", "p384", "/CN=example.com", "root_p384", LEAF, digest="sha512")
        k.cert("leaf_rsa384", "rsa", "/CN=example.com", "root_rsa", LEAF, digest="sha384")
        k.cert("leaf_expired", "p256", "/CN=example.com", "int_ec", LEAF, digest="sha384",
               start=NOW - 400 * DAY, end=NOW - 30 * DAY)
        k.cert("leaf_future", "p256", "/CN=example.com", "int_ec", LEAF, digest="sha384",
               start=NOW + 30 * DAY)
        k.cert("leaf_client", "p256", "/CN=example.com", "int_ec",
               LEAF.replace("serverAuth", "clientAuth"), digest="sha384")
        k.cert("leaf_noca", "p256", "/CN=example.com", "int_noca", LEAF)
        k.cert("leaf_noku", "p256", "/CN=example.com", "int_noku", LEAF)
        k.cert("leaf_via_client", "p256", "/CN=example.com", "int_client", LEAF)
        k.cert("leaf_deep", "p256", "/CN=example.com", "int_sub", LEAF)
        k.cert("leaf_critical", "p256", "/CN=example.com", "int_ec",
               LEAF + ";1.2.3.4.5=critical,ASN1:NULL", digest="sha384")
        k.cert("leaf_ip_only", "p256", "/CN=ip", "int_ec",
               LEAF.replace("DNS:example.com,DNS:*.example.com,", ""), digest="sha384")
        # A signature changed by one bit, and a copy of a root with another key.
        bad = bytearray(k.der["leaf_ec"])
        bad[-1] ^= 1
        k.der["leaf_badsig"] = bytes(bad)
        with open(k.path("leaf_badsig.pem"), "wb") as f:
            f.write(ossl("x509", "-inform", "DER", input=bytes(bad)).stdout)
        k.cert("root_rsa_other", "rsa", "/C=US/O=Goose Test/CN=Goose Root R1", ext=CA)

        for name in k.der:
            if name != "leaf_badsig":
                lines += fields(k, name)
        lines.append(f"cert leaf_badsig {k.der['leaf_badsig'].hex()}")

        def case(label, leaf, inters, roots, host, want, now=NOW):
            # openssl's verdict, which must agree on pass or fail.
            with open(k.path("ca.pem"), "w") as f:
                for r in roots:
                    f.write(open(k.path(f"{r}.pem")).read())
            with open(k.path("un.pem"), "w") as f:
                for i in inters:
                    f.write(open(k.path(f"{i}.pem")).read())
            args = ["verify", "-attime", str(now), "-purpose", "sslserver", "-CAfile", k.path("ca.pem"),
                    "-x509_strict"]
            if inters:
                args += ["-untrusted", k.path("un.pem")]
            if host != "-":
                if re.fullmatch(r"[0-9.]+", host):
                    args += ["-verify_ip", host]
                else:
                    args += ["-verify_hostname", host]
            p = ossl(*args, k.path(f"{leaf}.pem"), check=False)
            openssl_ok = p.returncode == 0
            assert openssl_ok == (want == "ok"), (label, p.stdout, p.stderr)
            cases.append(f"case {label} {leaf} {','.join(inters) or '-'} {','.join(roots)} {now} {host} {ERR[want]}")

        case("ec_chain", "leaf_ec", ["int_ec"], ["root_rsa"], "example.com", "ok")
        case("wildcard", "leaf_ec", ["int_ec"], ["root_rsa"], "www.example.com", "ok")
        case("ip", "leaf_ec", ["int_ec"], ["root_rsa"], "192.0.2.1", "ok")
        case("no_host_check", "leaf_ec", ["int_ec"], ["root_rsa"], "-", "ok")
        case("pss_chain", "leaf_pss", ["int_pss"], ["root_rsa"], "example.com", "ok")
        case("ed25519", "leaf_ed", [], ["root_ed"], "example.com", "ok")
        case("p384_sha512", "leaf_p384", [], ["root_p384"], "example.com", "ok")
        case("rsa_sha384", "leaf_rsa384", [], ["root_rsa"], "example.com", "ok")
        case("extra_intermediates", "leaf_ec", ["int_noca", "int_pss", "int_ec"], ["root_ed", "root_rsa"],
             "example.com", "ok")
        case("wrong_root_key", "leaf_ec", ["int_ec"], ["root_rsa_other"], "example.com", "bad_signature")
        case("two_roots_same_name", "leaf_ec", ["int_ec"], ["root_rsa_other", "root_rsa"], "example.com", "ok")
        case("missing_intermediate", "leaf_ec", [], ["root_rsa"], "example.com", "unknown_issuer")
        case("wrong_root", "leaf_ec", ["int_ec"], ["root_p384"], "example.com", "unknown_issuer")
        case("bad_signature", "leaf_badsig", ["int_ec"], ["root_rsa"], "example.com", "bad_signature")
        case("expired", "leaf_expired", ["int_ec"], ["root_rsa"], "example.com", "expired")
        case("not_yet_valid", "leaf_future", ["int_ec"], ["root_rsa"], "example.com", "not_yet_valid")
        case("chain_expired_later", "leaf_ec", ["int_ec"], ["root_rsa"], "example.com", "expired",
             now=NOW + 3651 * DAY)
        case("wrong_host", "leaf_ec", ["int_ec"], ["root_rsa"], "example.org", "hostname")
        case("wildcard_two_labels", "leaf_ec", ["int_ec"], ["root_rsa"], "a.b.example.com", "hostname")
        case("wildcard_apex", "leaf_ec", ["int_ec"], ["root_rsa"], "com", "hostname")
        case("wrong_ip", "leaf_ec", ["int_ec"], ["root_rsa"], "192.0.2.2", "hostname")
        case("ip_not_dns", "leaf_ip_only", ["int_ec"], ["root_rsa"], "example.com", "hostname")
        case("client_only", "leaf_client", ["int_ec"], ["root_rsa"], "example.com", "eku")
        case("issuer_not_ca", "leaf_noca", ["int_noca"], ["root_rsa"], "example.com", "not_ca")
        case("issuer_no_keycertsign", "leaf_noku", ["int_noku"], ["root_rsa"], "example.com", "key_usage")
        case("issuer_client_eku", "leaf_via_client", ["int_client"], ["root_rsa"], "example.com", "eku")
        case("path_length", "leaf_deep", ["int_sub", "int_ec"], ["root_rsa"], "example.com", "path_length")
        case("unknown_critical", "leaf_critical", ["int_ec"], ["root_rsa"], "example.com", "critical")
        case("root_as_leaf", "root_rsa", [], ["root_rsa"], "-", "key_usage")   # keyCertSign only

        # The RFC 8448 server certificate and its CertificateVerify, from
        # the tls package's vectors when they are beside this repository.
        rfc = os.path.join(ROOT, "..", "tlsgoose.git", "test", "vectors", "rfc8448.txt")
        if os.path.exists(rfc):
            v = dict(l.split() for l in open(rfc).read().splitlines())
            cert_msg = bytes.fromhex(v["server.construct_a_certificate_handshake_message.certificate"])
            cert = cert_msg[11:11 + int.from_bytes(cert_msg[8:11], "big")]
            cv = bytes.fromhex(v["server.construct_a_certificateverify_handshake_message.certificateverify"])
            import hashlib
            th = hashlib.sha256(b"".join(bytes.fromhex(v[x]) for x in (
                "client.construct_a_clienthello_handshake_message.clienthello",
                "server.construct_a_serverhello_handshake_message.serverhello",
                "server.construct_an_encryptedextensions_handshake_message.encryptedextensions",
                "server.construct_a_certificate_handshake_message.certificate"))).digest()
            content = b" " * 64 + b"TLS 1.3, server CertificateVerify\0" + th
            lines.append(f"rfc8448 {cert.hex()} {cv[4:6].hex()} {content.hex()} {cv[8:].hex()}")

    vec = os.path.join(ROOT, "test", "vectors")
    with open(os.path.join(vec, "certs.txt"), "w") as f:
        f.write("\n".join(lines + cases) + "\n")

    # The system root store.
    src = "/etc/ssl/cert.pem"
    if os.path.exists(src):
        shutil.copy(src, os.path.join(vec, "roots.pem"))
    pems = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                      open(os.path.join(vec, "roots.pem")).read(), re.S)
    out = []
    for i, pem in enumerate(pems):
        p = ossl("x509", "-noout", "-subject", "-nameopt", "RFC2253,-esc_msb", "-text",
                 input=pem.encode()).stdout.decode("utf-8")
        subject = p.splitlines()[0][len("subject="):]
        alg = re.search(r"Signature Algorithm: (\S+)", p).group(1)
        checkable = alg in ("sha256WithRSAEncryption", "sha384WithRSAEncryption",
                            "sha512WithRSAEncryption", "ecdsa-with-SHA256", "ecdsa-with-SHA384",
                            "ecdsa-with-SHA512", "ED25519", "rsassaPss")
        out.append(f"root {i} {int(checkable)} {subject.replace(' ', '%20') or '-'}")
    with open(os.path.join(vec, "roots.txt"), "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {len([l for l in lines if l.startswith('cert ')])} certificates, {len(cases)} path cases, "
          f"{len(out)} roots")


if __name__ == "__main__":
    main()
