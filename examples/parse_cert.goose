// Reading certificates: every certificate of a PEM file (a leaf and its
// CA, as a server sends them), with its subject, issuer, serial,
// validity, key, signature algorithm, usages and names; host name
// matching; and which certificate signed which. Without a file it reads
// example-chain.pem, a chain made by openssl, and checks what it holds.
//
//   goose examples/parse_cert.goose -- [FILE.pem]
import std;
import os;
import x509 from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";

fn date(t: i64) -> u8[>..] {
    let y, m, d = asn1::civil_from_days(t / 86400);
    var out: u8[>..] = [];
    format_int(out, y, 10, 4, '0');
    out.push('-');
    format_int(out, m, 10, 2, '0');
    out.push('-');
    format_int(out, d, 10, 2, '0');
    return out;
}

fn key_name(k: i64) -> const u8[:] {
    if k == x509::KEY_RSA { return "RSA"; }
    if k == x509::KEY_EC_P256 { return "ECDSA P-256"; }
    if k == x509::KEY_EC_P384 { return "ECDSA P-384"; }
    if k == x509::KEY_EC_P521 { return "ECDSA P-521"; }
    if k == x509::KEY_ED25519 { return "Ed25519"; }
    return "other";
}

fn sig_name(alg: i64) -> const u8[:] {
    if alg == x509::SIG_RSA_PKCS1 { return "RSA PKCS #1 v1.5"; }
    if alg == x509::SIG_RSA_PSS { return "RSA-PSS"; }
    if alg == x509::SIG_ECDSA { return "ECDSA"; }
    if alg == x509::SIG_ED25519 { return "Ed25519"; }
    if alg == x509::SIG_MLDSA { return "ML-DSA"; }
    return "other";
}

fn main() {
    let a = args();
    var text: u8[>..] = [];
    if a.len > 1 {
        guard read_file(a[1], text) else { print("parse_cert: cannot read ", a[1]); exit(1); }
    } else {
        text.append(embed_file("example-chain.pem"));
    }
    let ders, ok = asn1::pem_decode(text, "CERTIFICATE");
    guard ok && ders.len > 0 else { print("parse_cert: no certificate in the file"); exit(1); }

    // Parse each; a Cert keeps its own copy of the DER. Each one is also
    // checked as the signer of the one before it, as a chain is sent.
    var prev = x509::empty_cert();
    var leaf = x509::empty_cert();
    var i = 0;
    for der in ders {
        let c, e = x509::parse(der);
        guard e == x509::OK else { print("parse_cert: ", x509::error_text(e)); exit(1); }
        print("subject   ", x509::subject_text(c));
        print("issuer    ", x509::issuer_text(c));
        print("serial    ", x509::serial_hex(c));
        print("valid     ", date(c.not_before), " to ", date(c.not_after));
        print("key       ", key_name(c.key_type), "; signed with ", sig_name(c.sig_alg), " over SHA-", c.sig_hash);
        print("CA        ", c.is_ca, if c.path_len >= 0 { str(", path length ", c.path_len) } else { str("") });
        if c.has_key_usage {
            print("usage     ", if c.key_usage & x509::KU_DIGITAL_SIGNATURE != 0 { "digitalSignature " } else { "" },
                  if c.key_usage & x509::KU_KEY_CERT_SIGN != 0 { "keyCertSign " } else { "" },
                  if c.key_usage & x509::KU_CRL_SIGN != 0 { "cRLSign" } else { "" },
                  if c.ext_key_usage & x509::EKU_SERVER_AUTH != 0 { "; serverAuth" } else { "" });
        }
        for n in x509::dns_names(c) { print("DNS name  ", n); }
        // One attribute of the subject, by OID (2.5.4.10 is O).
        for o in x509::name_values(c.der, c.subject, "2.5.4.10") { print("O         ", o); }
        // SHA-256 of the DER: the fingerprint browsers show.
        var fp: u8[>..] = [];
        for b in bignum::hash_bits(256, c.der) { format_uint(fp, b, 16, 2, '0'); }
        print("sha256    ", fp);
        if i > 0 {
            let es = x509::check_signature(prev, c);
            print("signs     certificate ", i - 1, " (", x509::error_text(es), ")");
            guard es == x509::OK else { exit(1); }
        }
        if x509::self_issued(c) { print("self-sig  ", x509::error_text(x509::check_signature(c, c))); }
        if !c.is_ca { leaf = copy(c); }
        print("");
        prev = copy(c);
        i++;
    }

    // What the default file holds, checked.
    if a.len == 1 {
        guard ders.len == 2 && x509::matches_host(leaf, "www.example.com") && x509::matches_host(leaf, "example.com") &&
              !x509::matches_host(leaf, "mail.example.com") && leaf.key_type == x509::KEY_EC_P256 else {
            print("parse_cert: example-chain.pem did not read as expected");
            exit(1);
        }
        print("leaf matches www.example.com and example.com, not mail.example.com");
    }
}
