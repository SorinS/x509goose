# x509

X.509 certificates (RFC 5280) for the Goose language. It covers parsing,
names, subject alternative names, signature checks, host name matching
(RFC 6125), certification path validation for TLS servers with name
constraints, certificate policies and CRLs, and checking TLS 1.3
CertificateVerify signatures.

| Module | Holds |
|---|---|
| `x509` | `Cert`, parsing, names, SANs, host matching, signatures, `Options` |
| `x509.verify` | `verify_chain`, `verify_chain_with`, `verify_pools`, `verify_with_roots`, `verify_with_system_roots`, `verify_client_with_roots`, `verify_client_with_system_roots` |
| `x509.pool` | `CertPool`: certificates by subject and key identifier; loading from PEM, DER, files, directories and the system's root store |
| `x509.constraints` | name constraints |
| `x509.policy` | certificate policy processing |
| `x509.crl` | `Crl`, `parse_crl`, `check_crl`, `crl_lookup`, `revocation_status` |
| `x509.keys` | `PrivateKey`, key generation, PKCS #8 / SEC 1 / PKCS #1 / SPKI parsing and marshalling (ML-DSA and DSA included), signing |
| `x509.ocsp` | OCSP (RFC 6960): `ocsp_create_request`, `ocsp_parse_request`, `ocsp_parse_response`, `ocsp_check_response`, `ocsp_create_response`, `ocsp_error_response` |
| `x509.pkcs12` | `pkcs12_decode`: PKCS #12 files to their key and certificates |
| `x509.create` | `Template`, `create_certificate`, `name_der`, SAN and name-constraint builders, `create_csr`, `parse_csr`, `check_csr`, `create_crl` | It builds on
[asn1](../asn1goose.git) for DER and [bignum](../bigmongoose.git) for the
cryptography.

```goose
import x509 from "../x509goose.git";
import asn1 from "../asn1goose.git";        // x509 needs both; the root declares them
import bignum from "../bigmongoose.git";
import x509.verify;

let err = x509::verify_chain(leaf_der, intermediates_der, roots_der, now, "example.com");
if err != x509::OK { print("certificate refused: ", x509::error_text(err)); }

let leaf, e = x509::parse(leaf_der);
print(x509::subject_text(leaf), " ", x509::serial_hex(leaf));
for name in x509::dns_names(leaf) { print("  ", name); }
let ok = x509::verify_scheme(leaf, scheme, signed_content, signature) == x509::OK;
```

Lists of certificates (intermediates, roots) are DER certificates
concatenated back to back. DER marks where each one ends, so the
certificate list of a TLS Certificate message, or a PEM bundle run through
`asn1::pem_decode`, only needs appending.

## Parsing

`parse(der) -> Cert, err` and `parse_pem(text)` refuse malformed input:
- anything but strict DER, or trailing bytes;
- an inner signature algorithm that differs from the outer one;
- a version that doesn't match the fields present;
- the same extension twice, or a critical flag spelled out as FALSE;
- malformed basicConstraints, key usage, extended key usage, SAN or key
  identifiers.

A `Cert` keeps its own copy of the DER. Everything else is a decoded
scalar or an `asn1::Tlv` into that copy:
- version, serial, validity times;
- signature algorithm with its hash and PSS salt length;
- key type;
- the basic constraints, path length, key usage (`KU_*`) and extended key
  usage (`EKU_*`) bits;
- SAN and key identifiers;
- whether any critical extension went unrecognized.

| Signatures | Keys |
|---|---|
| RSA PKCS #1 v1.5 with SHA-256, SHA-384, SHA-512 | RSA (up to 4096 bits) |
| RSASSA-PSS with SHA-256, SHA-384, SHA-512 (MGF1 on the same hash) | ECDSA P-224, P-256, P-384, P-521 |
| ECDSA with SHA-256, SHA-384, SHA-512 | Ed25519 |
| Ed25519 | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| ML-DSA-44, ML-DSA-65, ML-DSA-87 (pure, empty context, RFC 9881) | DSA (p up to 3072 bits; parameters in the key) |
| DSA with SHA-224, SHA-256, SHA-384, SHA-512 | |

An ML-DSA signature must come from a key of the same parameter set
(`sig_hash` holds the set: 44, 65 or 87). Go 1.27 parses DSA keys but
checks no DSA signatures; here they are checked, as openssl does.

SHA-1 and other algorithms parse but fail when used, with
`ERR_UNSUPPORTED_ALGORITHM`.

## Names and hosts

`name_text(der, name)`, `subject_text` and `issuer_text` produce RFC 4514
text, most specific first, the way `openssl x509 -nameopt RFC2253` prints
it. `name_values(der, name, oid)` returns one attribute's values.
`dns_names` and `ip_addresses` list the SAN entries. `matches_host(c,
host)` takes a host name or an IPv4 literal and looks only at the SAN; the
commonName is not consulted. A wildcard must be a whole left-most label,
covers exactly one label, and needs at least two labels after it.

## Signatures and paths

`check_signature(c, issuer)` checks that issuer's key signed c.
`verify_scheme(c, scheme, msg, sig)` checks a TLS 1.3 SignatureScheme
signature with c's key: rsa_pkcs1_*, rsa_pss_rsae_*,
ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ecdsa_secp521r1_sha512
(with the curve bound to the scheme, as TLS 1.3 requires), and ed25519.

`verify_chain(leaf, intermediates, roots, now, host)` searches depth-first
for a path from the leaf through the intermediates to a root, and
backtracks past dead ends. If no path works, it returns the error of the
one that came closest. Each link must be signed by the certificate above
it, and every certificate on the path must be within its validity period
at `now` with no unknown critical extension. The CAs, roots included, must
have basicConstraints CA (a self-issued v1 root without basicConstraints
is accepted) and respect their path lengths. A CA that has key usage must
allow keyCertSign, and one that has extended key usage must allow
serverAuth. The leaf's own extended key usage, if present, must allow
serverAuth, and its key usage must allow a TLS key. `Options.key_usages`
(Go's KeyUsages, as `EKU_*` masks) changes the usage required of the leaf
and the CAs: any one of those given will do, and `EKU_ANY` accepts any. `host`, if not empty,
must match the leaf. A leaf that is itself one of the roots is accepted
as pinned.

`verify_chain_with(leaf, intermediates, roots, crls, now, host, opts)`
adds three checks on top of `verify_chain`, run on each complete path it
builds. If they fail, it keeps searching for another path.

The same search runs over pools (see below):
- `verify_pools(leaf, intermediates_pool, roots_pool, crls, now, host, opts)`
  is the general form;
- `verify_with_roots(leaf, intermediates, roots_pool, now, host)` takes
  the intermediates as concatenated DER;
- `verify_with_system_roots(leaf, intermediates, now, host)` uses the
  system's roots, loaded once;
- `verify_client_with_roots(leaf, intermediates, roots_pool, now)` and
  `verify_client_with_system_roots(leaf, intermediates, now)` check a TLS
  client certificate: clientAuth instead of serverAuth, and no host.

`verify_chain` and `verify_chain_with` build pools from their
concatenations. Candidate issuers are looked up by subject. Those whose
subject key identifier matches the authority key identifier are tried
first, so two roots of one name both work.

- **Name constraints** (RFC 5280 §4.2.1.10). Every CA's permitted and
  excluded subtrees, the root's included, bind every certificate below it
  except self-issued intermediates.
  - Supported forms: dNSName, rfc822Name (mailbox, host or `.domain`), URI
    hosts, iPAddress with mask, and directoryName. A directoryName is
    compared RDN by RDN, values case-folded, so a PrintableString and a
    UTF8String spelling of the same name match.
  - What is checked: the SAN entries and the subject, including any
    emailAddress in it.
  - Other forms (otherName and the rest) can't be evaluated, so a
    certificate is refused only if it has names of a form that is
    constrained.
- **Certificate policies** (§6.1). The policy tree is built from
  certificatePolicies, policyMappings, policyConstraints and
  inhibitAnyPolicy, and capped at 1,000 nodes. It is then intersected with
  `opts.policies`: dotted OIDs separated by spaces, empty for anyPolicy.
  `opts.require_explicit_policy`, `inhibit_policy_mapping` and
  `inhibit_any_policy` are the initial inputs. A CA's
  requireExplicitPolicy applies whatever the options say.
- **Revocation.** `opts.crl_check` takes `CRL_NONE`, `CRL_LEAF` or
  `CRL_ALL` (every certificate below the root). A CRL counts for a
  certificate only when all of these hold:
  - it names the certificate's issuer and is signed by that issuer's key;
  - the issuer's key usage, if present, allows cRLSign;
  - it is current at `now`;
  - its issuingDistributionPoint scope (user or CA certificates only)
    includes the certificate.

  A certificate listed in such a CRL is `ERR_REVOKED`. A certificate with
  no usable CRL is `ERR_REVOCATION_UNKNOWN`. Delta CRLs, indirect CRLs and
  CRLs partitioned by reason parse but are never used. `crl_urls(c)`
  lists a certificate's distribution points. OCSP is in `x509.ocsp`.

## Pools and the system's roots

`CertPool` corresponds to Go's `x509.CertPool`. It holds each
certificate once (up to 4,096), indexed by subject and key identifier.

| Go | Here |
|---|---|
| `NewCertPool` | `new_pool()` |
| `AddCert` | `pool_add(p, der)`, `pool_add_cert(p, cert)`, `pool_add_concatenated(p, list)` |
| `AppendCertsFromPEM` | `pool_append_pem(p, text)` (how many were new; blocks that do not parse are skipped) |
| `SystemCertPool` | `system_roots()` (loaded once; a copy each call), `load_system_roots()` (loaded afresh) |
| `Contains`, `len(Subjects())` | `pool_contains(p, der)`, `pool_len(p)` |
| | `pool_add_file(p, path)`, `pool_add_dir(p, dir)`, `pool_der`, `pool_cert`, `pool_issuers`, `pool_concatenated` |

`pool_add_file` reads a PEM file (any number of certificates) or a single
DER certificate. `pool_add_dir` reads every file of a directory, but not
its subdirectories, as openssl's and Go's certificate directories hold
them:
- hashed `c_rehash` names or any other names;
- files that hold no certificate are skipped;
- a certificate reached under two names is added once.

Both return how many certificates were new, or -1 if the path cannot be
read.

The system's roots are found as Go finds them on Unix:
- the file `$SSL_CERT_FILE`, else the first readable bundle of the
  Linux and BSD locations, the last of which, `/etc/ssl/cert.pem`, is
  macOS's;
- then every directory of `$SSL_CERT_DIR` (separated by `:`), else
  `/etc/ssl/certs`, `/etc/pki/tls/certs`, `/usr/local/share/certs` and
  `/etc/openssl/certs`.

The Windows certificate store is not read.

## Keys

`PrivateKey` holds an RSA key, an EC scalar (P-224, P-256, P-384, P-521),
an Ed25519 or ML-DSA seed (`seed`), or a DSA key (`dsa`). These
correspond to Go's functions:

| Go | Here |
|---|---|
| `ParsePKCS8PrivateKey`, `ParseECPrivateKey`, `ParsePKCS1PrivateKey` | `parse_private_key(der)` (any of the three) and `parse_private_key_pem` |
| `MarshalPKCS8PrivateKey`, `MarshalECPrivateKey`, `MarshalPKCS1PrivateKey` | `marshal_pkcs8`, `marshal_sec1`, `marshal_pkcs1` |
| `MarshalPKIXPublicKey` | `marshal_public_key` |
| `rsa.GenerateKey`, `ecdsa.GenerateKey`, `ed25519.GenerateKey`, `mldsa.GenerateKey`, `dsa.GenerateParameters` + `GenerateKey` | `generate_key(kind, bits = 2048)` (`bits` is p's size for DSA) |

The output matches openssl's byte for byte. ML-DSA private keys follow
RFC 9881 and Go:
- they are written as the seed alone (`[0]` IMPLICIT OCTET STRING), as
  Go and `openssl -provparam ml-dsa.output_formats=seed-only` write them;
- openssl's default form, the seed with the expanded key, is read when
  the two agree (Go refuses it);
- the expanded key without its seed is refused, as Go refuses it.

DSA keys go beyond Go, which has no DSA private keys in x509. Both
PKCS #8 and openssl's "DSA PRIVATE KEY" are read, and PKCS #8 is
written. DSA signatures use RFC 6979 nonces; ML-DSA signing is hedged. `sign(key, alg, hash, msg)`
signs in X.509's forms (ECDSA as DER), `sig_alg_id(alg, hash)` gives the
AlgorithmIdentifier, and `default_sig(kind)` gives the default algorithm.
As in Go, the default for RSA is PKCS #1 v1.5 with SHA-256, for ECDSA
it is the curve's own hash, and for ML-DSA the key's own set. For DSA it
is SHA-256, as in openssl.

## Creating certificates, requests and CRLs

```goose
import x509.keys;
import x509.create;

let key = x509::generate_key(x509::KEY_EC_P256);
var t, ok = x509::template("CN=www.example.com,O=Example", now, now + 90 * 86400);
t.key_usage = x509::KU_DIGITAL_SIGNATURE;
t.ext_key_usage = x509::EKU_SERVER_AUTH;
x509::add_dns(t.san, "www.example.com");
let der, err = x509::create_certificate(t, x509::marshal_public_key(key), ca_der, ca_key);
```

- **Fields.** A `Template` holds:
  - serial (random when empty), validity, and the subject as Name DER;
  - basic constraints with path length, and key usage and extended key
    usage masks;
  - SAN, permitted and excluded subtrees, policies, CRL URLs;
  - the signature algorithm (the issuer key's default if left 0), and
    raw `extra` extensions.
- **Names.** `name_der` builds a Name from RFC 4514 text, and the
  `add_dns` / `add_email` / `add_uri` / `add_ip` / `add_dirname` builders
  fill SANs and subtrees.
- **Extensions written.** Every certificate gets a subject key identifier
  (SHA-1 of the key, as Go and openssl compute it), and an authority key
  identifier from the issuer.
- **Checks before signing.** The issuer must be a CA allowed to sign
  certificates, and `issuer_key` must match the issuer certificate (or
  the subject's key, for a self-signed one). The result is parsed back
  before it is returned.
- **Requests.** `create_csr(subject, san, key)` makes a PKCS #10 request
  with an extensionRequest for the SAN. `parse_csr` reads one,
  `check_csr` checks its self-signature, and `csr_dns_names` lists its
  names.
- **CRLs.** `create_crl(issuer, key, entries, this_update, next_update,
  number)` makes a v2 CRL, with a reason code per entry, an authority key
  identifier and a CRL number.

## OCSP

`ocsp_create_request(cert, issuer, hash = 160)` makes the request Go's
`ocsp.CreateRequest` makes (one CertID, SHA-1 by default, or SHA-256, -384,
-512), and `ocsp_parse_request` reads its first CertID back.
`ocsp_parse_response(der, serial = "")` reads a response's structure and
its answer for that serial (or its only answer), without checking it;
`ocsp_check_response(r, cert, issuer, now = 0)` then requires a
successful response whose CertID names the certificate and its issuer,
signed by the issuer or by a responder certificate the issuer signed with
id-kp-OCSPSigning, and current, and gives OK (good), ERR_REVOKED, or
ERR_REVOCATION_UNKNOWN. The CertID and EKU checks are RFC 6960's and go
beyond Go's. `ocsp_create_response(issuer, responder, key, template,
produced_at, include_cert)` makes what Go's `ocsp.CreateResponse` makes,
byte for byte; `ocsp_error_response(status)` the unsuccessful ones.

## PKCS #12

`pkcs12_decode(pfx, password) -> key, certs, err` gives the private key
(PKCS #8 DER, for `parse_private_key`) and the certificates (DER
concatenated) of a .p12 or .pfx file, after checking its MAC (HMAC over
SHA-1, SHA-224 or SHA-2). It reads what Go's x/crypto/pkcs12 reads
(pbeWithSHAAnd3-KeyTripleDES-CBC, pbeWithSHAAnd40BitRC2-CBC) and what it
refuses: openssl 3's default PBES2 (PBKDF2 and AES-CBC), 2-key 3DES,
128-bit RC2, unencrypted bags. A wrong password is ERR_BAD_SIGNATURE.

## Tests

```bash
python3 scripts/run_tests.py [--native] # at -O0, -O2 and --debug (and natively)
python3 scripts/check_created.py        # x509.create's output against openssl and Go
python3 scripts/check_roots.py          # system roots against Go's rules
python3 scripts/gen_vectors.py          # regenerate the vectors with openssl
python3 scripts/pq_vectors.py           # remake vectors/pq.txt (openssl, Go)
python3 scripts/pkcs12_vectors.py       # remake the PKCS #12 vectors (openssl)
python3 scripts/make_rootdir.py         # remake vectors/rootdir
tools/govectors.sh > test/vectors/ocsp.txt   # remake the OCSP vectors (Go)
```

They take the compiler from `--goose`, `$GOOSE`, `goose` on PATH or
`../goose.git/build/goose`, and asn1goose.git and bigmongoose.git beside
this repository; the vector scripts need openssl 3.5 or later, and the Go
ones Go with golang.org/x/crypto v0.55.0 in the module cache (they run
offline). `tools/govectors.sh` builds `tools/govectors` and runs it with
its arguments.

- `cert_vectors`: a PKI made by openssl, with every supported signature
  algorithm and one certificate for each way a path fails. Each
  certificate's subject, issuer, serial, dates, SANs and constraints must
  parse as openssl prints them. Each of 29 path cases must give its
  expected result, and `openssl verify` agreed on pass or fail when the
  vectors were made. 32 more cases cover name constraints (each form, and
  excluded subtrees), policies (explicit, mapped, inhibited, required by
  a CA) and CRLs (revoked, missing, expired, wrong signer, an intermediate
  revoked). For those, openssl ran with `-policy_check`, the matching
  `-crl_check` flags and the same acceptable policies. Each CRL's dates,
  entries and number must parse as `openssl crl` prints them. RFC 8448's
  server CertificateVerify must verify under the trace's certificate, and
  fail under other schemes or when changed.
- `keys_create`: openssl's keys must round-trip through every DER form.
  A PKI made here is then checked: a root, a constrained intermediate,
  leaves on Ed25519, P-256, P-521 and P-224 signed with RSA PKCS #1 v1.5
  and RSA-PSS, a P-224 intermediate signing with ECDSA, a certificate
  issued from a CSR, and CRLs. Fields must read
  back, paths must validate (or fail on a name constraint or a
  revocation), and misuse must be refused.
- `pq_vectors`: ML-DSA and DSA (`scripts/pq_vectors.py`):
  - openssl's ML-DSA-44/65/87 keys in all three PKCS #8 forms, and DSA
    keys of each (L, N) in PKCS #8 and the traditional form, must parse,
    or be refused where they should be;
  - keys must marshal back to openssl's bytes, and Go's (from fixed
    seeds) to Go's;
  - ML-DSA and DSA hierarchies made by openssl and by Go must validate
    as openssl and Go said: ML-DSA-87 → 65 → 44 leaves, P-256 and DSA
    leaves under ML-DSA, and DSA signed with SHA-256 and SHA-224;
  - every key must sign a certificate here that checks, and TLS
    signatures under its scheme.

  `scripts/check_created.py` also has openssl verify an ML-DSA-65 root's
  ML-DSA-44, ML-DSA-87 and DSA leaves, a DSA root's leaf, and an ML-DSA
  CSR and CRL, all made here. Go's crypto/x509 verifies the ML-DSA ones
  and reads their keys.
- `pool_api`: adding certificates once, from DER, PEM, files, and
  `vectors/rootdir` (`scripts/make_rootdir.py`). The directory holds PEM
  and DER files, a c_rehash link, junk, a text file and a subdirectory
  that must be left alone. Also checked:
  - issuer lookup, key identifier first;
  - paths over pools, with two roots of one name;
  - the system's roots, loaded once and copied out.

  `scripts/check_roots.py` checks system root loading against Go's rules,
  with the environment as it is, with `SSL_CERT_FILE` and `SSL_CERT_DIR`
  set, and with nothing to find.
- `ocsp_vectors`: requests and responses made by Go's x/crypto/ocsp
  (`tools/govectors`): requests made here byte for byte and parsed back;
  good, revoked and unknown responses from the CA and from a delegated
  responder, parsed and checked (and refused for a responder without
  id-kp-OCSPSigning, another CA, the wrong certificate, too early or too
  late), then made here byte for byte; the error responses.
- `pkcs12_vectors`: 54 files from openssl (`scripts/pkcs12_vectors.py`):
  RSA and P-256 keys with their chains under nine schemes and three
  passwords, each decoding to openssl's key and certificates; wrong
  passwords and changed bytes refused. Go's x/crypto/pkcs12 reads the 12
  legacy ones to the same keys (and refuses the rest).
- `scripts/check_created.py` hands such a PKI to openssl (30 checks):
  - each leaf verifies strictly for the host and under an explicit
    policy, and is refused under another policy or host;
  - a leaf under the P-224 intermediate verifies;
  - the name constraints are enforced;
  - the CSR and both CRLs verify;
  - `-crl_check_all` finds the listed leaf revoked and the others good;
  - every private key matches its certificate.
- `constraints_api`: subtree matching at its edges (label boundaries,
  leading dots, case, URI hosts with userinfo and ports, IP families).
- `roots`: the 128 certificates of the system root store must all parse,
  and every subject must read exactly as openssl prints it. Every
  self-signature in a supported algorithm must verify (87 of them); the
  SHA-1 ones must be refused.
