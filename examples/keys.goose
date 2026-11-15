// Private and public keys: generating each kind, writing them as PKCS #8
// (and SEC 1 or PKCS #1, the older "EC/RSA PRIVATE KEY" forms) in PEM,
// reading them back, and signing with them in X.509's forms; then a
// signature over a digest the caller made, as TLS 1.2 does.
//
//   goose examples/keys.goose
import std;
import os;
import x509 from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import bignum.hmac;
import x509.keys;
import x509.create;

fn fail(what: const u8[:]) { print("keys: ", what); exit(1); }

// A certificate for a key, so verify_with can check its signatures.
fn self_signed(k: const x509::PrivateKey&) -> x509::Cert {
    let now = time() as i64;
    var t, ok = x509::template("CN=key holder", now, now + 86400);
    let der, e = x509::create_certificate(t, x509::marshal_public_key(k), "", k);
    let c, ep = x509::parse(der);
    guard ok && e == x509::OK && ep == x509::OK else { fail("self-signed certificate"); }
    return c;
}

// PKCS #8 PEM out and back, and a signature with the key's default
// algorithm checked against a certificate for it.
fn round_trip(name: const u8[:], k: const x509::PrivateKey&, ms: i64) {
    // PKCS #8 in PEM ("BEGIN PRIVATE KEY"), as openssl and Go write it.
    var pem: u8[>..] = [];
    asn1::pem_encode(pem, "PRIVATE KEY", x509::marshal_pkcs8(k));
    let k2, ok = x509::parse_private_key_pem(pem);
    guard ok && k2.kind == k.kind && x509::marshal_pkcs8(k2) == x509::marshal_pkcs8(k) else {
        fail(str(name, ": PKCS #8 round trip"));
    }
    // The public half, SubjectPublicKeyInfo ("BEGIN PUBLIC KEY").
    let spki = x509::marshal_public_key(k);

    let alg, h = x509::default_sig(k.kind);
    let sig, oks = x509::sign(k, alg, h, "a message");
    let c = self_signed(k);
    guard oks && x509::verify_with(c, alg, h, c.pss_salt, "a message", sig) == x509::OK &&
          x509::verify_with(c, alg, h, c.pss_salt, "another", sig) == x509::ERR_BAD_SIGNATURE else {
        fail(str(name, ": signature"));
    }
    print(name, ": made in ", ms, " ms; PKCS #8 ", x509::marshal_pkcs8(k).len, " bytes, public key ", spki.len,
          " bytes, signature ", sig.len, " bytes");
}

fn ms_since(t0: f64) -> i64 { ((clock() - t0) * 1000.0) as i64 }

fn main() {
    // DSA keys work the same way (generate_key(x509::KEY_DSA, 2048)), but
    // making their parameters takes seconds.
    var t0 = clock();
    let ec = x509::generate_key(x509::KEY_EC_P256);
    round_trip("P-256", ec, ms_since(t0));
    t0 = clock();
    let p384 = x509::generate_key(x509::KEY_EC_P384);
    round_trip("P-384", p384, ms_since(t0));
    t0 = clock();
    let ed = x509::generate_key(x509::KEY_ED25519);
    round_trip("Ed25519", ed, ms_since(t0));
    t0 = clock();
    let rsa = x509::generate_key(x509::KEY_RSA);          // 2048 bits by default
    round_trip("RSA-2048", rsa, ms_since(t0));
    t0 = clock();
    let pq = x509::generate_key(x509::KEY_MLDSA65);
    round_trip("ML-DSA-65", pq, ms_since(t0));

    // The older forms: SEC 1 for EC keys, PKCS #1 for RSA; parse_private_key
    // reads all three without being told which.
    let ec2, ok1 = x509::parse_private_key(x509::marshal_sec1(ec));
    let rsa2, ok2 = x509::parse_private_key(x509::marshal_pkcs1(rsa));
    guard ok1 && ok2 && x509::marshal_public_key(ec2) == x509::marshal_public_key(ec) &&
          x509::marshal_public_key(rsa2) == x509::marshal_public_key(rsa) else {
        fail("SEC 1 / PKCS #1");
    }
    let junk, okj = x509::parse_private_key("not a key");
    guard !okj else { fail("junk parsed as a key"); }
    print("SEC 1 and PKCS #1 read back; junk refused");

    // Over a digest: RSA-PSS with SHA-256, the hash made by the caller.
    let rc = self_signed(rsa);
    let digest = bignum::hash_bits(256, "handshake transcript");
    let ps, okp = x509::sign_digest(rsa, x509::SIG_RSA_PSS, 256, digest);
    guard okp && x509::verify_digest(rc, x509::SIG_RSA_PSS, 256, 32, digest, ps) == x509::OK else { fail("sign_digest"); }
    print("RSA-PSS over a SHA-256 digest verifies");
}
