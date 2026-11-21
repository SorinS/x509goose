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
| `x509.keys` | `PrivateKey`, key generation, PKCS #8 / SEC 1 / PKCS #1 / SPKI parsing and marshalling (brainpool, Ed448, X448, ML-DSA, SLH-DSA, ML-KEM and DSA included), signing |
| `x509.ocsp` | OCSP (RFC 6960): `ocsp_create_request`, `ocsp_parse_request`, `ocsp_parse_response`, `ocsp_check_response`, `ocsp_create_response`, `ocsp_error_response` |
| `x509.pkcs12` | `pkcs12_decode`: PKCS #12 files to their key and certificates; `pkcs12_encode`: a key and certificates to one |
| `x509.cms` | CMS SignedData (RFC 5652) with one signer: `cms_sign`, `cms_sign_with` (id-data, detached, signingTime, smimeCapabilities, key identifier, Ed25519, Ed448), `cms_unsigned`, `cms_parse_signed`, `cms_parse_signed_ber`, `cms_verify`, `cms_verify_detached`, `cms_signing_time`, `cms_content`, `cms_certs`, `cms_der` (BER to DER); ML-DSA signers (RFC 9882) and SHAKE digests; PKINIT's carrier and S/MIME's |
| `x509.cms_env` | CMS EnvelopedData and AuthEnvelopedData (RFC 5652 §6, RFC 5083/5084): `cms_encrypt`, `cms_decrypt`, `cms_content_type`; RSA-OAEP and PKCS #1 v1.5 key transport, ECDH key agreement (RFC 5753; NIST and brainpool curves), X448 key agreement (RFC 8418), ML-KEM recipients (KEMRecipientInfo, RFC 9629 and RFC 9936), AES-CBC and AES-GCM |
| `x509.create` | `Template`, `create_certificate`, `name_der`, SAN and name-constraint builders, `create_csr`, `parse_csr`, `check_csr`, `create_crl` | It builds on
[asn1](https://github.com/SorinS/asn1goose) for DER and [bignum](https://github.com/SorinS/bigmongoose) for the
cryptography.

```goose
import x509 from "SorinS/x509goose@v0.9.1";
import entropy from "SorinS/entropygoose@v0.9.1";   // x509 needs it; the root declares it
import bignum from "SorinS/bigmongoose@v0.9.1";
import asn1 from "SorinS/asn1goose@v0.9.1";
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
  identifiers; a SAN or name-constraint entry that is not a
  context-class GeneralName ([0] to [8], constructed or primitive as its
  form requires).

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
| ECDSA with SHA-256, SHA-384, SHA-512 | ECDSA brainpoolP256r1, P384r1, P512r1 (RFC 5639) |
| Ed25519 | Ed25519, Ed448 |
| Ed448 (pure, empty context, RFC 8410) | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| ML-DSA-44, ML-DSA-65, ML-DSA-87 (pure, empty context, RFC 9881) | DSA (p up to 3072 bits; parameters in the key) |
| DSA with SHA-224, SHA-256, SHA-384, SHA-512 | SLH-DSA, all twelve sets |
| SLH-DSA, all twelve sets: SHA2 and SHAKE, 128/192/256, s and f (pure, empty context, RFC 9909) | X448 and ML-KEM (they sign nothing: CMS recipients) |

An ML-DSA signature must come from a key of the same parameter set
(`sig_hash` holds the set: 44, 65 or 87), and an SLH-DSA one likewise
(`SIG_SLHDSA`, `sig_hash` the `bignum::SLHDSA_*` set, 1 to 12; the key
types are `KEY_SLHDSA_SHA2_128S` to `KEY_SLHDSA_SHAKE_256F`, with
`is_slhdsa`, `slhdsa_set` and `slhdsa_kind`). SLH-DSA has no TLS
SignatureScheme, so `verify_scheme` does not take it. Go 1.27 parses DSA keys but
checks no DSA signatures; here they are checked, as openssl does.

The brainpool curves are named curves under id-ecPublicKey
(1.3.36.3.3.2.8.1.1.7, .11 and .13: `KEY_EC_BP256`, `KEY_EC_BP384`,
`KEY_EC_BP512`; `is_brainpool`, and `is_ec` takes them with the NIST
ones), signing ECDSA with any of SHA-256, -384 and -512; secp256k1
(1.3.132.0.10, `KEY_EC_SECP256K1`) is one too, for KMIP and the like
(Go's crypto/x509 does not take it). Ed448
(`KEY_ED448`, `SIG_ED448`, id-Ed448 1.3.101.113) and X448 (`KEY_X448`,
id-X448 1.3.101.111) are RFC 8410's: parameters absent. The TLS 1.3
ECDSA schemes name a NIST curve, so `verify_scheme` refuses brainpool
keys under them; brainpool keys verify under RFC 8734's
ecdsa_brainpoolP256r1tls13_sha256, P384r1 and P512r1 (`ECDSA_BRAINPOOLP*`,
each bound to its curve), and Ed448 keys under ed448 (`ED448`, 0x0808).

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
(with the curve bound to the scheme, as TLS 1.3 requires), the brainpool
ones of RFC 8734 likewise, ed25519 and ed448.

`verify_chain(leaf, intermediates, roots, now, host)` searches depth-first
for a path from the leaf through the intermediates to a root, and
backtracks past dead ends. If no path works, it returns the error of the
one that came closest. As in Go, a certificate with the subject, key and
subjectAltName of one already on the path is not tried again, and one
search makes at most 100 signature checks (`ERR_TOO_MANY_SIGNATURES`
past that), so intermediates sent by a peer cannot buy unbounded work. Each link must be signed by the certificate above
it, and every certificate on the path must be within its validity period
at `now` with no unknown critical extension. The CAs, roots included, must
have basicConstraints CA (a self-issued v1 root without basicConstraints
is accepted) and respect their path lengths, which count the
non-self-issued intermediates below them (RFC 5280 §4.2.1.9: a CA's key
rollover certificate does not count). A CA that has key usage must
allow keyCertSign, and one that has extended key usage must allow
serverAuth. The leaf's own extended key usage, if present, must allow
serverAuth, and its key usage must allow a TLS key. `Options.key_usages`
(Go's KeyUsages, as `EKU_*` masks) changes the usage required of the leaf
and the CAs: any one of those given will do, as long as the leaf and
every CA allow it (absent or anyExtendedKeyUsage allows all), and
`EKU_ANY` accepts any. `host`, if not empty,
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
  - A wildcard dNSName `*.X` counts as every name under X against
    excluded subtrees: `*.example.com` is refused under an excluded
    `secret.example.com`.
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
    includes the certificate;
  - if its issuingDistributionPoint names a distribution point (a
    fullName), one of those names is among the fullNames of the
    certificate's CRL distribution points, the same DER (RFC 5280
    §6.3.3 (b)(2)(i)): another partition's CRL, or any partitioned CRL for
    a certificate without distribution points, does not count.

  A certificate listed in such a CRL is `ERR_REVOKED`. A certificate with
  no usable CRL is `ERR_REVOCATION_UNKNOWN`. Delta CRLs, indirect CRLs and
  CRLs partitioned by reason or named relative to the issuer parse but are
  never used. `crl_urls(c)`
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

`PrivateKey` holds an RSA key, an EC scalar (P-224, P-256, P-384, P-521,
brainpoolP256r1, P384r1, P512r1), an Ed25519 or ML-DSA seed (`seed`), an
Ed448 seed (57 bytes) or X448 key (56) in `key448`, an SLH-DSA key
(`slh`), or a DSA key (`dsa`). These
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

SLH-DSA keys (RFC 9909; Go has none) are the 4n-byte private key,
SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root, held in PKCS #8's privateKey OCTET
STRING as it is, and the 2n-byte public key in the SubjectPublicKeyInfo,
as openssl writes them. Reading a private key does not recompute PK.root
from the seeds, which would cost a key generation
(`bignum::slhdsa_check_key` does it). Signing is hedged; a key of an "s"
set takes seconds per signature (see bignum's README for timings).

Ed448 and X448 keys (Go has neither) are written in PKCS #8 as the seed
or key in an OCTET STRING, as Ed25519's and as openssl writes them; a
OneAsymmetricKey v2 with the public key is read too. Brainpool keys are
written as openssl writes them, in PKCS #8 and SEC 1.

DSA keys go beyond Go, which has no DSA private keys in x509. Both
PKCS #8 and openssl's "DSA PRIVATE KEY" are read, and PKCS #8 is
written. DSA signatures use RFC 6979 nonces; ML-DSA signing is hedged. `sign(key, alg, hash, msg)`
signs in X.509's forms (ECDSA as DER), and returns false, as Go's
`Sign` returns an error, when RSA's private operation fails its check
against the public key (a fault: the signature is never released);
`create_certificate`, `create_csr`, `create_crl` and
`ocsp_create_response` then give `ERR_SIGNING`. `sig_alg_id(alg, hash)` gives the
AlgorithmIdentifier, and `default_sig(kind)` gives the default algorithm.
`sign_digest(key, alg, hash, digest)` and `verify_digest(cert, alg, hash,
salt, digest, sig)` take a digest the caller made, as Go's `crypto.Signer`
does, for RSA, ECDSA and DSA (TLS 1.2's CertificateVerify hashes as the
handshake goes); Ed25519, Ed448, ML-DSA and SLH-DSA sign messages, so they give
false and `ERR_UNSUPPORTED_ALGORITHM`.
As in Go, the default for RSA is PKCS #1 v1.5 with SHA-256, for ECDSA
it is the curve's own hash (SHA-256, -384 and -512 for the three
brainpool curves), and for ML-DSA (and SLH-DSA) the key's own set. For DSA it
is SHA-256, as in openssl.

## Keys held elsewhere

A key in a TPM, on a PKCS#11 token or in a remote service is a
`PrivateKey` holding only its SubjectPublicKeyInfo: `external_key(spki)`,
or `external_key(cert)` for the key a certificate names; `is_external(k)`
says which. It stands for the key in configurations (its kind and
`marshal_public_key` are the real key's), and `sign` and `sign_digest`
refuse it. The calls that sign take a signer as their last argument,
which does the signing, as Go's crypto.Signer:

    F(key: const PrivateKey&, alg: i64, h: i64, data: const u8[:]) -> u8[>..]

alg is one of `SIG_*` and h the hash (`SIG_MLDSA` and `SIG_SLHDSA`: the
parameter set); data is the digest by h of what is signed, except for
the algorithms that sign the message itself (`signs_message`: Ed25519,
Ed448, ML-DSA, SLH-DSA), which get the message (`data_to_sign` makes
either). The signer returns the signature as `sign` would (RSA as is,
ECDSA and DSA as DER; RSA-PSS with a salt as long as the hash), or nothing
when it cannot sign. `sign_data` is the signer for keys in memory, which
the calls given none use, and `sign_with(k, alg, h, msg, F)` signs a
message through F. `create_certificate`, `create_csr`,
`create_csr_attrs`, `create_crl`, `ocsp_create_response`, `cms_sign` and
`cms_sign_with` take a signer; a certificate or CSR made through one has
its signature checked against the public key before it is returned
(`ERR_BAD_SIGNATURE` otherwise), as Go checks a crypto.Signer's. tpm2 and
pkcs11 give signers for their keys (`tpm2::sign_data`, `p11::sign_data`).
test/signer.goose makes a root, a CSR, a certificate, a CRL, an OCSP
response and CMS through a signer for P-256, P-384, RSA, Ed25519 and
ML-DSA-44 issuers, each checked.

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
  with an extensionRequest for the SAN, and OK or ERR_SIGNING. `parse_csr` reads one,
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
ERR_REVOCATION_UNKNOWN. A critical extension in the response or in its
SingleResponse is ERR_UNKNOWN_CRITICAL_EXTENSION at parsing (none is
implemented). A delegated responder's certificate must also be
within its validity at `now`, have no unknown critical extension, allow
digitalSignature if it has keyUsage, and be the one the ResponderID names
(by subject or by key hash). These checks are RFC 6960's (§4.2.2.2) and
go beyond Go's. `ocsp_create_response(issuer, responder, key, template,
produced_at, include_cert)` makes what Go's `ocsp.CreateResponse` makes,
byte for byte; `ocsp_error_response(status)` the unsuccessful ones.

## PKCS #12

`pkcs12_decode(pfx, password) -> key, certs, err` gives the private key
(PKCS #8 DER, for `parse_private_key`) and the certificates (DER
concatenated) of a .p12 or .pfx file, after checking its MAC (HMAC over
SHA-1, SHA-224 or SHA-2). It reads what Go's x/crypto/pkcs12 reads
(pbeWithSHAAnd3-KeyTripleDES-CBC, pbeWithSHAAnd40BitRC2-CBC) and what it
refuses: openssl 3's default PBES2 (PBKDF2 and AES-CBC), 2-key 3DES,
128-bit RC2, unencrypted bags. A wrong password is ERR_BAD_SIGNATURE. A
file without a MAC is read only with the empty password; under any other
it is ERR_BAD_SIGNATURE, as in Go, since nothing would hold its contents
to the password.

`pkcs12_encode(key, certs, password, iterations = 2048) -> pfx, err`
writes one as openssl 3 does by default: the key (PKCS #8 DER, or empty)
in a shrouded key bag and the certificates (DER concatenated, the key's
first) in an encrypted SafeContents, both under PBES2 with PBKDF2 over
HMAC-SHA-256 and AES-256-CBC, the whole under an HMAC-SHA-256 MAC keyed
by the PKCS #12 KDF; the key and its certificate share a localKeyID.
openssl 4.1 reads what it writes (the MAC, the key, the certificate; a
wrong password refused). A password with a character past U+FFFF, which
the KDF cannot take, is ERR_MALFORMED.

## CMS SignedData

`cms_sign(content_type, content, key, signer, others, alg, h)` makes a
ContentInfo holding a SignedData (version 3) with the content
encapsulated, the signer's certificate and `others` in `certificates`,
and one SignerInfo (issuer and serial number) with the signed attributes
contentType and messageDigest, by PKCS #1 v1.5, PSS or ECDSA over
SHA-256, -384 or -512. `cms_unsigned` makes one with no certificates and
no signer (anonymous PKINIT). `cms_parse_signed(der) -> SignedData, err`
reads strict DER with at most one signer; `cms_verify(sd, allow_sha1)`
finds the signer's certificate among those sent (by issuer and serial or
by key identifier), requires both signed attributes once with one value
each (contentType the eContentType's, messageDigest the content's),
takes rsaEncryption with the digest algorithm or a signature algorithm
whose hash is the digest algorithm, and checks the signature over the
attributes' DER (SET OF tag). SHA-1 only with `allow_sha1`. The signer's
certificate path and usages are the caller's to check.

## CMS for S/MIME

`cms_sign_with(..., o: CmsSignOptions)` is `cms_sign` with options:
`detached` (eContent left out), `signing_time` (the signingTime
attribute, UTCTime through 2049), `capabilities` (smimeCapabilities) and
`by_key_id` (the signer by subject key identifier, SignerInfo version 3);
it signs by Ed25519 too (RFC 8419: SHA-512 digest), and by Ed448 (RFC
8419: the digest id-shake256-len with 512 output bits, `CMS_SHAKE256_LEN`,
written with its INTEGER parameter; pure Ed448 over the attributes, no
context). Reading, an Ed448 signer's digest is id-shake256-len (512) or
id-shake256 (RFC 8419 §3.2's, without signed attributes, as openssl
signs). openssl's cms reads neither id-shake256-len nor signs Ed448
with attributes, so `scripts/check_curves.py` checks ours with its
primitives. Brainpool signers are ECDSA as on the NIST curves. Over id-data the
SignedData is version 1. `cms_verify_detached(sd, content)` checks a
detached signature; over id-data signed attributes may be absent, the
signature then over the content. `cms_der` turns BER (indefinite lengths,
constructed OCTET STRINGs) into DER, as mail clients send CMS.

For RFC 3161 time-stamp tokens (gslib's `tsp`), `CmsSignOptions` also has
`extra_attrs` (more signed attributes, whole Attribute elements laid end
to end: signingCertificateV2) and `no_certs` (no `certificates`, for a
request without certReq), and `cms_verify_with_certs(sd, more_certs)`
looks for the signer's certificate among the caller's as well as those
sent.

For SCEP (gslib's `scep`) and EST (`est`): `cms_signed_attr(sd, oid)`
gives one signed attribute's value (refusing one there twice or with
other than one value), `cms_certs_only(certs, crls)` makes a certs-only
SignedData and `cms_crls(sd)` reads its CRLs; `cms_sign_with` signs by
SHA-1 with an RSA key when h is 160 (signature algorithm rsaEncryption),
for SCEP servers that know nothing newer; `cms_encrypt` makes
DES-EDE3-CBC (`CMS_DES3_CBC`) and with `any_usage` encrypts to an RSA
certificate whose key usage leaves out keyEncipherment (a SCEP CA's);
`cms_decrypt_legacy` also reads DES-EDE3-CBC and single DES-CBC, which
`cms_decrypt` refuses. create.goose's `create_csr_attrs` adds attributes
to a CSR (challengePassword) and `csr_attribute` reads one back.

`cms_encrypt(content_type, content, recipients, o)` encrypts to
certificates (DER laid end to end): RSA by RSAES-OAEP with SHA-256 and
MGF1-SHA-256 (or PKCS #1 v1.5 with `rsa_pkcs1`), EC P-256/384/521 and
brainpoolP256r1/P384r1/P512r1 by ephemeral-static ECDH, the X9.63 KDF
over SHA-256/384/512 as the curve (dhSinglePass-stdDH-shaNNNkdf-scheme)
and AES key wrap of the content key's size; X448 by RFC 8418 (the
originator's key under id-X448, the X9.63 KDF over SHA-512, or
HKDF-SHA512 with `x448_hkdf`, then AES key wrap; openssl's cms has no X448
key agreement, so it is checked against openssl's primitives); the content by AES-128/256-CBC (EnvelopedData) or
AES-128/256-GCM (AuthEnvelopedData, 16-byte tags). `cms_decrypt(der, key,
cert)` finds the certificate's RecipientInfo (issuer and serial, or key
identifier) and reads what openssl writes: OAEP with SHA-1 or SHA-2,
PKCS #1 v1.5 by implicit rejection (a malformed block decrypts the
content under a random key, so the error is the content's, not the
padding's), openssl's default SHA-1 ECDH KDF, RFC 8418's HKDF-SHA256,
-384 and -512 (the ukm as the salt), AES-192, BER. Its own
errors are ERR_CMS_NOT_RECIPIENT and ERR_CMS_DECRYPT.

### Post-quantum

ML-DSA signs (RFC 9882): `cms_sign_with(..., SIG_MLDSA, h, o)` with an
ML-DSA-44, -65 or -87 key signs the signed attributes by pure ML-DSA with
the empty context; the digest is SHA-512 (`h` 0 or 512; 256, 384 or
`CMS_SHAKE256` when asked), the signature algorithm id-ml-dsa-NN with no
parameters. Reading, the digest may be SHA-256, -384, -512, SHAKE128
(32 bytes) or SHAKE256 (64 bytes; openssl's default for ML-DSA), and
without signed attributes the signature is over the content.

ML-KEM is encrypted to (RFC 9936): a certificate with an ML-KEM-512,
-768 or -1024 key (`KEY_MLKEM512`, `KEY_MLKEM768`, `KEY_MLKEM1024`; RFC
9935, OIDs 2.16.840.1.101.3.4.4.1-3; keyEncipherment if it has a key
usage) gets a KEMRecipientInfo (RFC 9629) inside an OtherRecipientInfo
(id-ori-kem): the KEM ciphertext, HKDF-SHA256 over the shared secret with
CMSORIforKEMOtherInfo as its info, and the content key AES-key-wrapped
by a key of its own size, as openssl does; `CmsEncryptOptions.kem_ukm`
adds a ukm. The EnvelopedData is then version 3. `cms_decrypt` reads
HKDF-SHA256, -384 and -512, a ukm, and the recipient by issuer and serial
or key identifier; a wrong key of the right set fails at the key unwrap
(ML-KEM's implicit rejection gives it a wrong secret, not an error).
ML-KEM private keys are read in all three PKCS #8 forms openssl writes
(the 64-byte seed `[0]`, the expanded key, both), kept as the expanded
key (`kem_dk`) with the seed when known (`kem_seed`), and written as the
seed when known, else the expanded key. Both directions are checked
against openssl 4.1 by mail's `scripts/interop_smime.py`.

SLH-DSA (RFC 9814) is not in CMS yet.

## Examples

In `examples/`, run from the repository's top as `goose examples/<name>.goose`
(or from that folder); each checks its own results.

- `parse_cert.goose`: a PEM chain's certificates taken apart, host matching, and which signed which (`example-chain.pem`, or a file of your own).
- `make_ca.goose`: a private CA: root, intermediate and server certificate, verified; an optional DIR gets the PEM files.
- `keys.goose`: P-256, P-384, Ed25519, RSA and ML-DSA keys: generating, PKCS #8 PEM, SEC 1 and PKCS #1, signing.
- `new_curves.goose`: a brainpoolP384r1 CA issuing an Ed448 server certificate and an X448 one; the Ed448 key through PKCS #8 PEM and back, the chain verified for its host name, CMS SignedData by Ed448 and AuthEnvelopedData to X448; a wrong host, a changed certificate and a changed signature refused. An optional DIR gets the PEM files, which `openssl verify` accepts.
- `slhdsa_cert.goose`: an SLH-DSA-SHA2-128f CA and an SLH-DSA-SHAKE-128f server certificate it issues, written as PEM (key in PKCS #8), read back and verified for the host name; a changed certificate refused. An optional DIR gets the PEM files, which `openssl verify` accepts.
- `verify_pool.goose`: path building over root and intermediate pools, name constraints, policies, and key usages.
- `csr.goose`: a CSR made, checked against a name policy and issued; a changed one refused.
- `crl.goose`: a CRL issued, read and looked up, and path validation with revocation checking.
- `ocsp.goose`: an OCSP request and response, client and responder in one process, with a delegated responder.
- `pkcs12.goose`: a .p12 read (`example.p12`, password `goose`), its key matched to its certificate, written again under a new password and read back, and the key written as PKCS #8.
- `cms_signed.goose`: CMS SignedData with ECDSA and RSA-PSS: signing, verifying signer and path, refusing changed content.
- `cms_pq.goose`: post-quantum CMS with keys made on the spot: SignedData by ML-DSA-65 with its path to an ML-DSA CA, and AuthEnvelopedData to an ML-KEM-768 certificate; a changed signature and a wrong key refused.
- `system_roots.goose`: the OS's root store loaded and used, with a private root added to a copy.

## Tests

```bash
python3 scripts/run_tests.py [--native] # at -O0, -O2 and --debug (and natively)
python3 scripts/check_created.py        # x509.create's output against openssl and Go
python3 scripts/check_curves.py         # brainpool, Ed448 and X448 output against openssl
python3 scripts/check_roots.py          # system roots against Go's rules
python3 scripts/gen_vectors.py          # regenerate the vectors with openssl
python3 scripts/pq_vectors.py           # remake vectors/pq.txt (openssl, Go) and pq_slhdsa.txt
python3 scripts/pq_vectors.py slhdsa    # remake vectors/pq_slhdsa.txt alone (openssl)
python3 scripts/curves_vectors.py       # remake vectors/curves.txt (openssl)
python3 scripts/pkcs12_vectors.py       # remake the PKCS #12 vectors (openssl)
python3 scripts/cms_vectors.py          # remake vectors/cms.txt (openssl cms -sign)
python3 scripts/check_cms.py            # x509.cms's SignedData through openssl cms -verify
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
- `pq_vectors`: ML-DSA, SLH-DSA and DSA (`scripts/pq_vectors.py`):
  - openssl's ML-DSA-44/65/87 keys in all three PKCS #8 forms, and DSA
    keys of each (L, N) in PKCS #8 and the traditional form, must parse,
    or be refused where they should be;
  - keys must marshal back to openssl's bytes, and Go's (from fixed
    seeds) to Go's;
  - ML-DSA and DSA hierarchies made by openssl and by Go must validate
    as openssl and Go said: ML-DSA-87 → 65 → 44 leaves, P-256 and DSA
    leaves under ML-DSA, and DSA signed with SHA-256 and SHA-224;
  - every key must sign a certificate here that checks, and TLS
    signatures under its scheme;
  - SLH-DSA (`vectors/pq_slhdsa.txt`): openssl's keys of all twelve sets
    must parse and marshal back to its PKCS #8 and SubjectPublicKeyInfo,
    keys a byte short or under another set's OID be refused; openssl's
    hierarchies signed with the "s" sets (SHA2-128s → SHAKE-192s →
    SHA2-256s and P-256 leaves, SHAKE-256s → SHAKE-128s → SHA2-192s,
    SHA2-256s over a SHAKE-256f leaf) must validate as openssl said, a
    wrong issuer key and a missing root among them; the "f" sets' keys,
    openssl's and two made here, sign certificates that check (the "s"
    sets take seconds to sign, so they only verify here).

  `scripts/check_created.py` also has openssl verify an ML-DSA-65 root's
  ML-DSA-44, ML-DSA-87 and DSA leaves, a DSA root's leaf, and an ML-DSA
  CSR and CRL, all made here. Go's crypto/x509 verifies the ML-DSA ones
  and reads their keys. openssl also verifies an SLH-DSA-SHAKE-128f
  root's SLH-DSA-SHA2-128f leaf, an SLH-DSA CSR and CRL made here, and
  reads the leaf's PKCS #8 key.
- `curves_vectors`: brainpool, Ed448 and X448 (`scripts/curves_vectors.py`,
  262 checks):
  - openssl's brainpoolP256r1/P384r1/P512r1 keys in PKCS #8 and SEC 1, and
    Ed448 and X448 keys in PKCS #8 (and as OneAsymmetricKey v2 with the
    public key), must parse and marshal back to its bytes and
    SubjectPublicKeyInfo; short keys and the other curve's OID refused;
  - openssl's hierarchies (brainpoolP512r1 → P384r1 → Ed448, P256r1 and
    X448 leaves; Ed448 root → brainpoolP384r1 leaf) validate as `openssl
    verify` said, a wrong issuer key, a missing root and a wrong host among
    them; its brainpool and Ed448 requests and CRLs check, each CRL
    revoking its leaf; its PKCS #12 files give the key;
  - its SignedData by brainpool signers (SHA-256/384/512, no attributes, by
    key identifier) and by Ed448 without attributes, and one by Ed448 with
    them built from its primitives (RFC 8419), verify, and refuse a changed
    content; its EnvelopedData to brainpool recipients (its SHA-1 and
    SHA-384 KDFs, GCM, key identifier, three recipients), and ones to X448
    built from its primitives (X9.63 SHA-512, HKDF-SHA512 with a ukm,
    HKDF-SHA256), decrypt, and not for another recipient or a wrong key;
  - keys of each kind made here sign certificates, requests and CMS that
    check (X448 refused), OCSP responses by a brainpool and an Ed448 CA
    check, and EnvelopedData to brainpool and X448 together
    (X9.63 or HKDF, CBC or GCM) decrypts for each.

  `scripts/check_curves.py` has openssl check what is made here (38
  checks): the leaves under a brainpoolP512r1 root and an Ed448 one, keys
  in PKCS #8 and SEC 1, brainpool and Ed448 requests and CRLs (revocation
  found), brainpool SignedData verified and changed refused, EnvelopedData
  decrypted per brainpool recipient; the Ed448 SignedData and the X448
  recipients (X9.63 and HKDF) with openssl's primitives, which its cms
  lacks.
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
- `path_rules`: the rules over a whole path, on certificates made here:
  - a CA's key rollover (a self-issued certificate for the new key,
    signed by the old) fits under path length 0, another CA does not;
    under path length 1, a rollover and one CA fit, two CAs do not;
  - of `Options.key_usages`, one must be allowed by every certificate: a
    server-only leaf under a client-only CA, or under a client-only root,
    is refused for server or client authentication or both; a
    server-only CA, or one with anyExtendedKeyUsage, passes;
  - the search backs up from a path that leaves no usage to another
    path that does, at the root and one level below it.

  `scripts/check_created.py` has openssl agree on the rollover, the CA
  beyond path length 0, and the server-only leaf under a client-only CA
  (refused as sslserver and as sslclient) and under a server-only one.
- `ocsp_vectors`: requests and responses made by Go's x/crypto/ocsp
  (`tools/govectors`): requests made here byte for byte and parsed back;
  good, revoked and unknown responses from the CA and from a delegated
  responder, parsed and checked (and refused for a responder without
  id-kp-OCSPSigning, another CA, the wrong certificate, too early or too
  late), then made here byte for byte; the error responses; delegated
  responders made here, refused expired, not yet valid, or with a
  keyUsage that leaves out digitalSignature; a response the issuer signed
  that names another responder.
- `pkcs12_vectors`: 54 files from openssl (`scripts/pkcs12_vectors.py`):
  RSA and P-256 keys with their chains under nine schemes and three
  passwords, each decoding to openssl's key and certificates; wrong
  passwords and changed bytes refused, the files without a MAC refused
  under a password. Go's x/crypto/pkcs12 reads the 12
  legacy ones to the same keys (and refuses the rest). Each key and its
  certificates are written again with `pkcs12_encode` and read back.
- `cms_vectors`: SignedData from `openssl cms -sign` (24, from
  `scripts/cms_vectors.py`): RSA (PKCS #1 v1.5 and PSS), P-256, P-384 and
  P-521 over SHA-256, -384 and -512, signers by issuer and serial and by
  key identifier, verify with their content and type; SHA-1 refused (and
  taken when allowed), no signed attributes, no signer certificate, two
  signers, a changed signature or content refused. SignedData made here
  by each key and algorithm verify here and refuse a changed byte;
  `scripts/check_cms.py` has `openssl cms -verify` check them (30 checks).
- `cms_smime`: SignedData and EnvelopedData from `openssl cms`
  (`test/cms_smime/vectors.txt`, from mail's `scripts/interop_smime.py
  --write-vectors`): signed detached and not, by RSA v1.5 and PSS, P-256 by
  key identifier, P-384, Ed25519, without attributes and in BER;
  encrypted by RSA v1.5, OAEP with SHA-1 and SHA-256, ECDH with the SHA-1
  and SHA-256 KDFs, GCM, several recipients, BER, each decrypting for its
  recipients only. Then made here every way and read back; changed bytes,
  wrong keys and non-recipients refused; BER to DER. Post-quantum, from
  `test/cms_smime/pq_vectors.txt` (mail's `scripts/interop_smime.py
  --write-pq-vectors`): ML-DSA-44/65/87 and ML-KEM-512/768/1024 keys in
  each PKCS #8 form openssl writes, written back as it does; SignedData by
  ML-DSA over SHAKE256, SHA-512 and SHA-256, without attributes, by key
  identifier, in BER; EnvelopedData and AuthEnvelopedData to ML-KEM with
  HKDF-SHA256/384/512, a ukm, AES-128/192/256, by key identifier, several
  recipients, BER. Then signed by ML-DSA and encrypted to every ML-KEM set
  (an RSA recipient beside them, with and without a ukm) here and read
  back; a wrong key of the same set, a changed KEM ciphertext, a signing
  certificate as recipient refused (465 checks).
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
