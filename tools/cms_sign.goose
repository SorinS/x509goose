// SignedData made by x509.cms for scripts/check_cms.py to hand to
// openssl: for each key in test/vectors/cms.txt and each algorithm it
// signs with, a line "NAME-ALG-HASH CMS_HEX" (the content is "AuthPack, say",
// its type id-pkinit-authData).
import std;
import x509 from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509.keys;
import x509.cms;

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn hex(b: const u8[:]) -> u8[>..] {
    let digits = "0123456789abcdef";
    var out: u8[>..] = [];
    for x in b { out.push(digits[(x >> 4) as i64]); out.push(digits[(x & 15) as i64]); }
    return out;
}

fn main() {
    for line in split(embed_file("../test/vectors/cms.txt"), '\n') {
        let w = words(line);
        if w.len == 0 || w[0] != "key" { continue; }
        let cert, e = x509::parse(unhex(w[2]));
        let key, ok = x509::parse_private_key(unhex(w[3]));
        assert(e == x509::OK && ok);
        var hs: i64[3] = [256, 384, 512];
        for h in hs {
            var algs: i64[>..] = [];
            if key.kind == x509::KEY_RSA { algs.push(x509::SIG_RSA_PKCS1); algs.push(x509::SIG_RSA_PSS); }
            else { algs.push(x509::SIG_ECDSA); }
            for alg in algs {
                let signed, oks = x509::cms_sign("1.3.6.1.5.2.3.1", "AuthPack, say", key, cert, "", alg, h);
                assert(oks);
                print(w[1], "-", if alg == x509::SIG_RSA_PSS { "pss" } else if alg == x509::SIG_ECDSA { "ecdsa" } else { "pkcs1" }, "-", h, " ", hex(signed));
            }
        }
    }
}
