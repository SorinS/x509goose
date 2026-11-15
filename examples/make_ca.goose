// A private CA: a self-signed root, an issuing intermediate under it, and
// a TLS server certificate for www.example.com from the intermediate,
// each with its key. The chain is verified for its host name, and the
// certificates and keys are written as PEM into a directory if one is
// given (as a web server would load them).
//
//   goose examples/make_ca.goose -- [DIR]
import std;
import os;
import x509 from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509.keys;
import x509.create;
import x509.verify;

let DAY: i64 = 86400;

fn fail(what: const u8[:], e: i64) { print("make_ca: ", what, ": ", x509::error_text(e)); exit(1); }

fn save(dir: const u8[:], name: const u8[:], label: const u8[:], der: const u8[:]) {
    var pem: u8[>..] = [];
    asn1::pem_encode(pem, label, der);
    guard write_file(str(dir, "/", name), pem) else { print("make_ca: cannot write ", dir, "/", name); exit(1); }
    print("wrote ", dir, "/", name);
}

fn main() {
    let now = time() as i64;

    // The root: self-signed (no issuer certificate), a CA, allowed to sign
    // certificates and CRLs. Its key never leaves the CA.
    let root_key = x509::generate_key(x509::KEY_EC_P384);
    var rt, okr = x509::template("CN=Example Root CA,O=Example,C=US", now - DAY, now + 20 * 365 * DAY);
    rt.is_ca = true;
    rt.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    let root, er = x509::create_certificate(rt, x509::marshal_public_key(root_key), "", root_key);
    guard okr && er == x509::OK else { fail("root", er); }

    // The intermediate: issues leaves, but no further CAs (path length 0).
    let int_key = x509::generate_key(x509::KEY_EC_P256);
    var it, oki = x509::template("CN=Example Issuing CA 1,O=Example,C=US", now - DAY, now + 5 * 365 * DAY);
    it.is_ca = true;
    it.path_len = 0;
    it.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    let inter, ei = x509::create_certificate(it, x509::marshal_public_key(int_key), root, root_key);
    guard oki && ei == x509::OK else { fail("intermediate", ei); }

    // The server's certificate: 90 days, its names in the SAN, for TLS
    // server authentication only.
    let leaf_key = x509::generate_key(x509::KEY_EC_P256);
    var lt, okl = x509::template("CN=www.example.com,O=Example", now - 60, now + 90 * DAY);
    lt.key_usage = x509::KU_DIGITAL_SIGNATURE;
    lt.ext_key_usage = x509::EKU_SERVER_AUTH;
    x509::add_dns(lt.san, "www.example.com");
    x509::add_dns(lt.san, "example.com");
    let leaf, el = x509::create_certificate(lt, x509::marshal_public_key(leaf_key), inter, int_key);
    guard okl && el == x509::OK else { fail("leaf", el); }

    let lc, ep = x509::parse(leaf);
    print("issued ", x509::subject_text(lc), " serial ", x509::serial_hex(lc));
    print("    by ", x509::issuer_text(lc));

    // A client checks it as TLS would: chain to the root, and the name.
    let ok1 = x509::verify_chain(leaf, inter, root, now, "www.example.com");
    let ok2 = x509::verify_chain(leaf, inter, root, now, "example.com");
    let bad_host = x509::verify_chain(leaf, inter, root, now, "mail.example.com");
    let no_inter = x509::verify_chain(leaf, "", root, now, "www.example.com");
    let expired = x509::verify_chain(leaf, inter, root, now + 91 * DAY, "www.example.com");
    print("www.example.com: ", x509::error_text(ok1), "; mail.example.com: ", x509::error_text(bad_host));
    print("without the intermediate: ", x509::error_text(no_inter), "; in 91 days: ", x509::error_text(expired));
    guard ok1 == x509::OK && ok2 == x509::OK && bad_host == x509::ERR_HOSTNAME && no_inter == x509::ERR_UNKNOWN_ISSUER &&
          expired == x509::ERR_EXPIRED else {
        print("make_ca: verification gave an unexpected result");
        exit(1);
    }

    // A leaf cannot issue: the library refuses before signing.
    var bt, okb = x509::template("CN=evil.example.com", now, now + DAY);
    let other = x509::generate_key(x509::KEY_EC_P256);
    let bogus, eb = x509::create_certificate(bt, x509::marshal_public_key(other), leaf, leaf_key);
    guard eb == x509::ERR_KEY_USAGE else { fail("a leaf issued a certificate", eb); }

    // What a server loads: its chain (leaf first) and its key.
    let a = args();
    if a.len > 1 {
        var chain: u8[>..] = [];
        asn1::pem_encode(chain, "CERTIFICATE", leaf);
        asn1::pem_encode(chain, "CERTIFICATE", inter);
        guard write_file(str(a[1], "/server-chain.pem"), chain) else { print("make_ca: cannot write to ", a[1]); exit(1); }
        save(a[1], "server.key", "PRIVATE KEY", x509::marshal_pkcs8(leaf_key));
        save(a[1], "root.pem", "CERTIFICATE", root);
    }
    print("CA made and its leaf verified");
}
