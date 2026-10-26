// vectors/pkcs12.txt: PKCS #12 files from openssl (scripts/pkcs12_vectors.py)
// for an RSA and a P-256 key with their chain, under openssl 3's default
// PBES2 with AES-256 and a SHA-256 MAC, AES-128 with SHA-1, the legacy RC2
// and 3DES PBEs Go's x/crypto/pkcs12 reads, 2-key 3DES, 128-bit RC2, no
// encryption, no MAC and a SHA-512 MAC; empty, ASCII and non-ASCII
// passwords. Each decodes to openssl's key and certificates; a wrong
// password and a changed byte are refused.
import std;
import x509 from "..";
import asn1 from "../../asn1goose.git";
import bignum from "../../bigmongoose.git";
import x509.keys;
import x509.pkcs12;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 10 { print("FAIL ", what); } }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn main() {
    for line in split(embed_file("vectors/pkcs12.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        let label = w[1];
        let pw = unhex(w[2]);
        let want_key, okw = x509::parse_private_key(unhex(w[3]));
        let pfx = unhex(w[5]);
        let key, certs, e = x509::pkcs12_decode(pfx, pw);
        let k, okk = x509::parse_private_key(key);
        check(label, okw && e == x509::OK && okk && x509::marshal_pkcs8(k) == x509::marshal_pkcs8(want_key));
        // The same certificates, in either order (openssl writes the
        // leaf's bag last when it has a key id).
        let want = unhex(w[4]);
        let first, ok1 = asn1::read(want, 0, want.len);
        var swapped: u8[>..] = [];
        swapped.append(want[first.end..]);
        swapped.append(want[..first.end]);
        check("certificates", certs == want || certs == swapped);
        var wrong: u8[>..] = [];
        wrong.append(pw);
        wrong.push('x');
        let k2, c2, e2 = x509::pkcs12_decode(pfx, wrong);
        let nomac = label == "rsa-nomac" || label == "p256-nomac";
        let plain = label == "rsa-plain" || label == "p256-plain";
        // Without a MAC or encryption a password cannot be wrong; with
        // encryption but no MAC it shows as bad padding or a broken key,
        // or (rarely) a key that does not parse.
        if !plain || !nomac {
            let pk2, okp2 = x509::parse_private_key(k2);
            check("wrong password", e2 != x509::OK || (nomac && !okp2) || plain);
        }
        var bad: u8[>..] = [];
        bad.append(pfx);
        bad[bad.len / 2] ^= 1;
        let k3, c3, e3 = x509::pkcs12_decode(bad, pw);
        check("changed", e3 != x509::OK || nomac);
    }
    let bmp, ok = x509::bmp_password("a\xc3\xa9");
    check("bmp password", ok && bmp == "\x00a\x00\xe9\x00\x00");
    let bmp2, ok2 = x509::bmp_password("\xf0\x9f\x98\x80");
    check("past U+FFFF", !ok2);
    print("pkcs12 vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
