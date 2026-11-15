// SLH-DSA (FIPS 205, RFC 9909) in X.509: a CA on an SLH-DSA-SHA2-128f
// key, self-signed, and a server certificate it issues for a key of
// another set; both written as PEM (key in PKCS #8, certificates), read
// back, and the chain verified for its host name. A changed certificate
// is refused. The "f" sets sign in a fraction of a second; the "s" sets
// (KEY_SLHDSA_SHA2_128S and so on) give certificates a third the size but
// take seconds to sign. If a directory is given, the PEM files go there,
// for `openssl verify -CAfile slh_ca.pem slh_server.pem`.
//
//   goose examples/slhdsa_cert.goose -- [DIR]
import std;
import os;
import x509 from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509.keys;
import x509.create;
import x509.verify;

let DAY: i64 = 86400;

fn fail(what: const u8[:]) { print("slhdsa_cert: ", what); exit(1); }

fn ms_since(t0: f64) -> i64 { ((clock() - t0) * 1000.0) as i64 }

fn pem(label: const u8[:], der: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    asn1::pem_encode(out, label, der);
    return out;
}

// The one certificate in a PEM text, as DER.
fn cert_from_pem(text: const u8[:]) -> u8[>..] {
    let ders, ok = asn1::pem_decode(text, "CERTIFICATE");
    guard ok && ders.len == 1 else { fail("PEM certificate"); }
    var out: u8[>..] = [];
    for d in ders { out.append(d); }
    return out;
}

fn main() {
    let a = args();
    let now = time() as i64;

    // The CA: an SLH-DSA-SHA2-128f key and a self-signed certificate.
    var t0 = clock();
    let ca_key = x509::generate_key(x509::KEY_SLHDSA_SHA2_128F);
    var ct, okc = x509::template("CN=Example SLH-DSA CA,O=Example", now - DAY, now + 10 * 365 * DAY);
    ct.is_ca = true;
    ct.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    let ca_der, ec = x509::create_certificate(ct, x509::marshal_public_key(ca_key), "", ca_key);
    guard okc && ec == x509::OK else { fail("CA certificate"); }
    print("CA: SLH-DSA-SHA2-128f, certificate ", ca_der.len, " bytes, made in ", ms_since(t0), " ms");

    // The server's key, of another set, and its certificate from the CA.
    t0 = clock();
    let srv_key = x509::generate_key(x509::KEY_SLHDSA_SHAKE_128F);
    var st, oks = x509::template("CN=www.example.com,O=Example", now - DAY, now + 90 * DAY);
    st.key_usage = x509::KU_DIGITAL_SIGNATURE;
    st.ext_key_usage = x509::EKU_SERVER_AUTH;
    x509::add_dns(st.san, "www.example.com");
    let srv_der, es = x509::create_certificate(st, x509::marshal_public_key(srv_key), ca_der, ca_key);
    guard oks && es == x509::OK else { fail("server certificate"); }
    print("server: SLH-DSA-SHAKE-128f, certificate ", srv_der.len, " bytes, made in ", ms_since(t0), " ms");

    // PEM out, and back in.
    let key_pem = pem("PRIVATE KEY", x509::marshal_pkcs8(srv_key));
    let ca_pem = pem("CERTIFICATE", ca_der);
    let srv_pem = pem("CERTIFICATE", srv_der);
    if a.len > 1 {
        let files = ["slh_ca.pem", "slh_server.pem", "slh_server.key"];
        for i in 3 {
            let body = if i == 0 { ca_pem[..] } else if i == 1 { srv_pem[..] } else { key_pem[..] };
            guard write_file(str(a[1], "/", files[i]), body) else { fail(str("cannot write ", a[1], "/", files[i])); }
            print("wrote ", a[1], "/", files[i]);
        }
    }
    let k2, okk = x509::parse_private_key_pem(key_pem);
    guard okk && k2.kind == x509::KEY_SLHDSA_SHAKE_128F && k2.slh == srv_key.slh else { fail("PKCS #8 read back"); }
    let srv2 = cert_from_pem(srv_pem);
    let c, ep = x509::parse(srv2);
    guard ep == x509::OK && c.sig_alg == x509::SIG_SLHDSA && c.key_type == x509::KEY_SLHDSA_SHAKE_128F &&
          x509::marshal_public_key(k2) == srv2[c.spki.start..c.spki.end] else {
        fail("certificate read back");
    }
    print("key and certificates read back from PEM; the key is the certificate's");

    // The chain, for its host name.
    let roots = cert_from_pem(ca_pem);
    t0 = clock();
    let e = x509::verify_chain(srv2, "", roots, now, "www.example.com");
    guard e == x509::OK else { fail(str("chain: ", x509::error_text(e))); }
    print("chain verified for www.example.com in ", ms_since(t0), " ms");
    guard x509::verify_chain(srv2, "", roots, now, "www.example.org") != x509::OK else { fail("wrong host accepted"); }

    // A certificate changed after signing (a byte of its validity) fails.
    var bad = copy(srv2);
    bad[c.tbs.end - 40] ^= 1;
    guard x509::verify_chain(bad, "", roots, now, "www.example.com") != x509::OK else { fail("changed certificate accepted"); }
    print("wrong host and changed certificate refused");
}
