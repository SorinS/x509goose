# x509

X.509 certificates (RFC 5280) for the Goose language. It covers parsing,
names, subject alternative names, signature checks, host name matching
(RFC 6125), certification path validation for TLS servers with name
constraints, certificate policies and CRLs, and checking TLS 1.3
CertificateVerify signatures.

| Module | Holds |
|---|---|
| `x509` | `Cert`, parsing, names, SANs, host matching, signatures, `Options` |
| `x509.verify` | `verify_chain`, `verify_chain_with` |
| `x509.constraints` | name constraints |
| `x509.policy` | certificate policy processing |
| `x509.crl` | `Crl`, `parse_crl`, `check_crl`, `crl_lookup`, `revocation_status` | It builds on
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
| RSASSA-PSS with SHA-256, SHA-384, SHA-512 (MGF1 on the same hash) | ECDSA P-256, P-384 |
| ECDSA with SHA-256, SHA-384, SHA-512 | Ed25519 |
| Ed25519 | |

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
ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384 (with the curve bound to
the scheme, as TLS 1.3 requires), and ed25519.

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
serverAuth, and its key usage must allow a TLS key. `host`, if not empty,
must match the leaf. A leaf that is itself one of the roots is accepted
as pinned.

`verify_chain_with(leaf, intermediates, roots, crls, now, host, opts)`
adds three checks on top of `verify_chain`, run on each complete path it
builds. If they fail, it keeps searching for another path.

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
  lists a certificate's distribution points. OCSP is not implemented.

## Tests

```bash
python3 scripts/run_tests.py [--native]
python3 scripts/gen_vectors.py          # regenerate the vectors with openssl
```

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
- `constraints_api`: subtree matching at its edges (label boundaries,
  leading dots, case, URI hosts with userinfo and ports, IP families).
- `roots`: the 128 certificates of the system root store must all parse,
  and every subject must read exactly as openssl prints it. Every
  self-signature in a supported algorithm must verify (87 of them); the
  SHA-1 ones must be refused.
