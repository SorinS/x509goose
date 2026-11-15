// Certificate requests (PKCS #10): an applicant makes a key and a CSR
// naming its subject and DNS names, and keeps the key; the CA parses the
// CSR, checks its self-signature (proof that the applicant holds the
// key), reads the names, and issues a certificate for that key and those
// names. A changed CSR fails its check.
//
//   goose examples/csr.goose
import std;
import os;
import x509 from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509.keys;
import x509.create;
import x509.verify;

let DAY: i64 = 86400;

fn fail(what: const u8[:], e: i64) { print("csr: ", what, ": ", x509::error_text(e)); exit(1); }

fn main() {
    let now = time() as i64;

    // The applicant: a key, and a request for two names. RFC 4514 text,
    // with an escaped comma in O.
    let key = x509::generate_key(x509::KEY_EC_P256);
    let subject, oks = x509::name_der("CN=shop.example.com,O=Example\\, Inc.,C=US");
    var san: u8[..4096] = [];
    x509::add_dns(san, "shop.example.com");
    x509::add_dns(san, "pay.example.com");
    let csr, ec = x509::create_csr(subject, san, key);
    guard oks && ec == x509::OK else { fail("create_csr", ec); }
    var pem: u8[>..] = [];
    asn1::pem_encode(pem, "CERTIFICATE REQUEST", csr);
    print(pem);

    // The CA: parse and check it, then look at what is asked for.
    let ders, okp = asn1::pem_decode(pem, "CERTIFICATE REQUEST");
    var got: u8[>..] = [];
    for d in ders { got.append(d); }
    let r, er = x509::parse_csr(got);
    guard okp && er == x509::OK else { fail("parse_csr", er); }
    let chk = x509::check_csr(r);
    guard chk == x509::OK else { fail("check_csr", chk); }
    var holder = x509::empty_cert();
    holder.der.append(r.der);
    print("request for ", x509::name_text(holder.der, r.subject), " (signature ", x509::error_text(chk), ")");
    for n in x509::csr_dns_names(r) { print("  DNS name ", n); }

    // Policy decisions are the CA's: here, every name under example.com.
    for n in x509::csr_dns_names(r) {
        let dot = ".example.com";
        guard n.len > dot.len && n[n.len - dot.len..] == dot else { print("csr: refusing ", n); exit(1); }
    }

    // A CA to sign with.
    let ca_key = x509::generate_key(x509::KEY_EC_P256);
    var ct, okc = x509::template("CN=Example Issuing CA,O=Example", now - DAY, now + 365 * DAY);
    ct.is_ca = true;
    ct.key_usage = x509::KU_KEY_CERT_SIGN;
    let ca, eca = x509::create_certificate(ct, x509::marshal_public_key(ca_key), "", ca_key);
    guard okc && eca == x509::OK else { fail("CA", eca); }

    // Issue: the subject, key and SAN straight from the request; the
    // validity and usages from the CA.
    var t, okt = x509::template("", now - 60, now + 90 * DAY);
    t.subject.clear();
    t.subject.append(r.der[r.subject.start..r.subject.end]);
    t.san.append(r.der[r.san.off..r.san.end]);
    t.key_usage = x509::KU_DIGITAL_SIGNATURE;
    t.ext_key_usage = x509::EKU_SERVER_AUTH;
    let cert, ei = x509::create_certificate(t, r.der[r.spki.start..r.spki.end], ca, ca_key);
    guard okt && ei == x509::OK else { fail("issue", ei); }
    let c, epc = x509::parse(cert);
    print("issued ", x509::subject_text(c), " serial ", x509::serial_hex(c));
    let v = x509::verify_chain(cert, "", ca, now, "pay.example.com");
    guard v == x509::OK && c.der[c.spki.start..c.spki.end] == x509::marshal_public_key(key) else { fail("verify", v); }
    print("it verifies for pay.example.com and holds the applicant's key");

    // One changed byte and the request no longer proves possession.
    var bad = copy(csr);
    bad[bad.len - 10] ^= 1;
    let br, ebr = x509::parse_csr(bad);
    guard ebr != x509::OK || x509::check_csr(br) != x509::OK else { print("csr: a changed request passed"); exit(1); }
    print("a changed request is refused");
}
