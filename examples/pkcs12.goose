// Reading a PKCS #12 file (.p12 or .pfx), as browsers, Windows and Java
// export a key with its certificates: decode it with its password, parse
// the private key and the certificates, and check that the key belongs to
// the leaf certificate by signing with it. A wrong password is refused.
// Without arguments it reads example.p12 (made by openssl 4 with its
// defaults, PBES2 with AES-256 and a SHA-256 MAC; password "goose").
//
//   goose examples/pkcs12.goose -- [FILE.p12 PASSWORD]
import std;
import os;
import x509 from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509.keys;
import x509.pkcs12;

fn main() {
    let a = args();
    var pfx:      u8[>..] = [];
    var password: u8[>..] = [];
    if a.len > 2 {
        guard read_file(a[1], pfx) else { print("pkcs12: cannot read ", a[1]); exit(1); }
        password.append(a[2]);
    } else {
        pfx.append(embed_file("example.p12"));
        password.append("goose");
    }

    // The key comes out as PKCS #8 DER, the certificates as DER back to back.
    let key_der, certs, e = x509::pkcs12_decode(pfx, password);
    guard e == x509::OK else { print("pkcs12: ", x509::error_text(e)); exit(1); }
    let key, okk = x509::parse_private_key(key_der);
    guard okk else { print("pkcs12: the key does not parse"); exit(1); }
    print("private key: kind ", key.kind, ", ", key_der.len, " bytes of PKCS #8");

    // Walk the certificates; the leaf is the one whose public key is ours.
    let spki = x509::marshal_public_key(key);
    var leaf = x509::empty_cert();
    var n = 0;
    var off = 0;
    while off < certs.len {
        let t, ok = asn1::read(certs, off, certs.len);
        guard ok else { print("pkcs12: bad certificate list"); exit(1); }
        let c, ec = x509::parse(certs[t.start..t.end]);
        guard ec == x509::OK else { print("pkcs12: ", x509::error_text(ec)); exit(1); }
        let mine = c.der[c.spki.start..c.spki.end] == spki;
        print("certificate: ", x509::subject_text(c), if mine { "  <- the key's" } else { "" });
        if mine { leaf = copy(c); }
        off = t.end;
        n++;
    }
    guard leaf.der.len > 0 else { print("pkcs12: no certificate for the key"); exit(1); }

    // Prove the pair works: sign with the key, verify with the certificate.
    let alg, h = x509::default_sig(key.kind);
    let sig, oks = x509::sign(key, alg, h, "proof of possession");
    guard oks && x509::verify_with(leaf, alg, h, 0, "proof of possession", sig) == x509::OK else {
        print("pkcs12: the key does not match its certificate");
        exit(1);
    }
    print("key matches ", x509::subject_text(leaf), "; ", n, " certificates in all");

    // A wrong password fails the MAC check: ERR_BAD_SIGNATURE.
    var wrong: u8[>..] = [];
    wrong.append(password);
    wrong.push('!');
    let k2, c2, e2 = x509::pkcs12_decode(pfx, wrong);
    guard e2 != x509::OK else { print("pkcs12: a wrong password was taken"); exit(1); }
    print("wrong password: ", x509::error_text(e2));

    // To keep the key on its own, as a server wants it: PKCS #8 PEM.
    var pem: u8[>..] = [];
    asn1::pem_encode(pem, "PRIVATE KEY", x509::marshal_pkcs8(key));
    print("as PEM: ", pem.len, " bytes beginning ", pem[..27]);
}
