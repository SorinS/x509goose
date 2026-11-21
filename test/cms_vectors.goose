// x509.cms against vectors/cms.txt (scripts/cms_vectors.py): SignedData
// made by `openssl cms -sign` with RSA (PKCS #1 v1.5 and PSS), P-256,
// P-384 and P-521 keys over SHA-256, -384 and -512, signers named by
// issuer and serial or by key identifier, must read and verify, with the
// content and its type intact; SHA-1, no signed attributes, no signer
// certificate, two signers and changed bytes must be refused as the
// vectors say. Then SignedData made here, by each key and algorithm, must
// verify here, and refuse a changed byte (scripts/check_cms.py has
// openssl verify them too); the unsigned form must read back unsigned.
import std;
import x509 from "..";
import entropy from "SorinS/entropygoose@v0.9.1";
import bignum from "SorinS/bigmongoose@v0.9.1";
import asn1 from "SorinS/asn1goose@v0.9.1";
import x509.keys;
import x509.cms;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 15 { print("FAIL ", what); } }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn result_name(e: i64) -> const u8[:] {
    if e == x509::OK { return "ok"; }
    if e == x509::ERR_MALFORMED { return "malformed"; }
    if e == x509::ERR_UNSUPPORTED_ALGORITHM { return "unsupported"; }
    if e == x509::ERR_UNKNOWN_ISSUER { return "unknown-issuer"; }
    if e == x509::ERR_BAD_SIGNATURE { return "bad-signature"; }
    return "other";
}

fn oid_text(der: const u8[:], t: asn1::Tlv) -> u8[>..] {
    let s, ok = asn1::read_oid(der, t);
    return s;
}

// Signs with a key every way it can, verifies, and refuses a changed byte.
fn round_trip(name: const u8[:], cert_der: const u8[:], key_der: const u8[:]) {
    let cert, e = x509::parse(cert_der);
    let key, ok = x509::parse_private_key(key_der);
    check("key parses", e == x509::OK && ok);
    let content = "AuthPack, say";
    var hs: i64[3] = [256, 384, 512];
    for h in hs {
        var algs: i64[>..] = [];
        if key.kind == x509::KEY_RSA { algs.push(x509::SIG_RSA_PKCS1); algs.push(x509::SIG_RSA_PSS); }
        else { algs.push(x509::SIG_ECDSA); }
        for alg in algs {
            let signed, oks = x509::cms_sign("1.3.6.1.5.2.3.1", content, key, cert, "", alg, h);
            let sd, ep = x509::cms_parse_signed(signed);
            let signer, ev = x509::cms_verify(sd);
            let d = sd.der[..];
            check(name, oks && ep == x509::OK && ev == x509::OK && x509::cms_content(sd) == content
                  && oid_text(d, sd.content_type) == "1.3.6.1.5.2.3.1" && signer.der == cert.der
                  && x509::cms_certs(sd) == cert_der);
            // Every byte of the signed attributes and signature matters.
            var bad: u8[>..] = [];
            bad.append(signed);
            bad[bad.len - 3] ^= 0x10;
            let sd2, ep2 = x509::cms_parse_signed(bad);
            let s2, ev2 = x509::cms_verify(sd2);
            check("changed signature", ep2 != x509::OK || ev2 != x509::OK);
        }
    }
}

fn main() {
    var seen = 0;
    for line in split(embed_file("vectors/cms.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        if w[0] == "key" {
            round_trip(w[1], unhex(w[2]), unhex(w[3]));
            continue;
        }
        let label = w[1];
        let want = w[2];
        let content = unhex(w[4]);
        let cert = unhex(w[6]);
        let sd, ep = x509::cms_parse_signed(unhex(w[5]));
        var got = ep;
        var signer_ok = true;
        if ep == x509::OK {
            let signer, ev = x509::cms_verify(sd);
            got = ev;
            if ev == x509::OK { signer_ok = signer.der == cert; }
            let d = sd.der[..];
            check(label, oid_text(d, sd.content_type) == w[3] && (x509::cms_content(sd) == content || want == "bad-signature"));
        }
        check(label, result_name(got) == want && signer_ok);
        if result_name(got) != want { print("  ", label, ": got ", result_name(got), ", want ", want); }
        // SHA-1 when asked for.
        if want == "unsupported" {
            let s1, e1 = x509::cms_verify(sd, true);
            check(label, e1 == x509::OK && s1.der == cert);
        }
        seen++;
    }
    check("vectors read", seen == 24);
    let u = x509::cms_unsigned("1.3.6.1.5.2.3.1", "anonymous");
    let sd, ep = x509::cms_parse_signed(u);
    let s, ev = x509::cms_verify(sd);
    check("unsigned", ep == x509::OK && !x509::cms_signed(sd) && x509::cms_content(sd) == "anonymous"
          && x509::cms_certs(sd).len == 0 && ev == x509::ERR_MALFORMED);
    print("cms vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
