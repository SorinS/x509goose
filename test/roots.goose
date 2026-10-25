// The system's root store (vectors/roots.pem, from /etc/ssl/cert.pem):
// every certificate must parse, its subject must read as openssl prints
// it, and its self-signature must check where the algorithm is one this
// package supports (SHA-1 ones are refused as unsupported).
import std;
import x509 from "..";
import asn1 from "../../asn1goose.git";
import bignum from "../../bigmongoose.git";
import x509.verify;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 15 { print("FAIL ", what); } }
}

// %20 back to spaces.
fn unspace(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < s.len {
        if i + 2 < s.len && s[i] == '%' && s[i + 1] == '2' && s[i + 2] == '0' { out.push(' '); i += 3; }
        else { out.push(s[i]); i++; }
    }
    return out;
}

fn main() {
    let ders, ok = asn1::pem_decode(embed_file("vectors/roots.pem"), "CERTIFICATE");
    check("pem", ok);
    var want: u8[][>..] = [];
    var checkable: bool[>..] = [];
    for line in split(embed_file("vectors/roots.txt"), '\n') {
        let w = words(line);
        if w.len < 4 { continue; }
        checkable.push(w[2] == "1");
        want.push(unspace(w[3]));
    }
    check("count", ders.len == checkable.len);
    var i = 0;
    var verified = 0;
    var subjects: u8[][>..] = [];
    for der in ders {
        let c, e = x509::parse(der);
        check("parse", e == x509::OK);
        subjects.push(x509::subject_text(c));
        let se = x509::check_signature(c, c);
        if checkable[i] {
            check("self signature", se == x509::OK);
            if se == x509::OK { verified++; }
        } else {
            check("unsupported", se == x509::ERR_UNSUPPORTED_ALGORITHM);
        }
        i++;
    }
    var j = 0;
    for s in subjects {
        var expect: u8[>..] = [];
        var k = 0;
        for x in want { if k == j { expect = copy(x); } k++; }
        check(expect, s == expect);
        if s != expect && failures <= 15 { print("   got ", s); }
        j++;
    }
    print("roots: ", ders.len, " parsed, ", verified, " self-signatures verified, ", checks, " checks, ",
          failures, " failed");
    assert(failures == 0);
}
