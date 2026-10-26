// vectors/ocsp.txt, from Go's x/crypto/ocsp (scripts/govectors): requests
// for SHA-1, -256, -384 and -512 CertIDs, made here byte for byte and
// parsed back; responses (good, revoked with and without a reason,
// unknown; signed by the CA, by a delegated responder carrying its
// certificate, by one without id-kp-OCSPSigning, by another CA) parsed,
// checked, and made again here byte for byte where the signature is
// deterministic; and the unsuccessful status responses.
import std;
import x509 from "..";
import asn1 from "../../asn1goose.git";
import bignum from "../../bigmongoose.git";
import x509.keys;
import x509.ocsp;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 10 { print("FAIL ", what); } }
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

fn num(s: const u8[:]) -> i64 {
    let v, ok = parse_int(s, 10);
    assert(ok);
    return v;
}

fn field(kind: const u8[:], name: const u8[:]) -> u8[>..] {
    for line in split(embed_file("vectors/ocsp.txt"), '\n') {
        let w = words(line);
        if w.len >= 3 && w[0] == kind && w[1] == name { return unhex(w[2]); }
    }
    var none: u8[>..] = [];
    assert(false);
    return none;
}

fn load(name: const u8[:]) -> x509::Cert {
    let c, e = x509::parse(field("cert", name));
    assert(e == x509::OK);
    return c;
}

fn main() {
    let ca = load("ca");
    let now: i64 = 1793000000;
    for line in split(embed_file("vectors/ocsp.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        if w[0] == "request" {
            let leaf = load("leaf");
            let h = num(w[1]);
            let der = unhex(w[2]);
            check("request", x509::ocsp_create_request(leaf, ca, h) == der);
            let id, ok = x509::ocsp_parse_request(der);
            let want = x509::ocsp_cert_id(leaf, ca, h);
            check("parse request", ok && id.hash == h && id.name_hash == want.name_hash && id.key_hash == want.key_hash &&
                  id.serial == want.serial);
        } else if w[0] == "response" {
            let name = w[1];
            let signer = w[2];
            let about = load(w[3]);
            let status = num(w[4]);
            let der = unhex(w[12]);
            let r, e = x509::ocsp_parse_response(der);
            check(name, e == x509::OK && r.response_status == x509::OCSP_SUCCESS && r.status == status &&
                  r.id.hash == num(w[5]) && r.this_update == num(w[6]) && r.next_update == num(w[7]) &&
                  r.revoked_at == num(w[8]) && r.reason == num(w[9]) && r.has_cert == (w[10] == "true") &&
                  r.produced_at == num(w[11]));
            // By serial: this certificate's answer, and none for another.
            let rs, es = x509::ocsp_parse_response(der, about.der[about.serial.off..about.serial.end]);
            check("by serial", es == x509::OK && rs.status == status);
            let rn, en = x509::ocsp_parse_response(der, "\x01");
            check("other serial", en == x509::ERR_REVOCATION_UNKNOWN);
            var want = x509::OK;
            if signer == "noeku" { want = x509::ERR_EXTENDED_KEY_USAGE; }
            else if signer == "other" { want = x509::ERR_BAD_SIGNATURE; }
            else if status == x509::OCSP_REVOKED { want = x509::ERR_REVOKED; }
            else if status == x509::OCSP_UNKNOWN { want = x509::ERR_REVOCATION_UNKNOWN; }
            let got = x509::ocsp_check_response(r, about, ca, now);
            check(name, got == want);
            if want == x509::OK || want == x509::ERR_REVOKED {
                // The wrong certificate, too early, too late.
                let other = load(if w[3] == "leaf" { "leaf2" } else { "leaf" });
                check("wrong certificate", x509::ocsp_check_response(r, other, ca, now) == x509::ERR_UNKNOWN_ISSUER);
                check("before thisUpdate", x509::ocsp_check_response(r, about, ca, r.this_update - 1) == x509::ERR_NOT_YET_VALID);
                if r.next_update >= 0 {
                    check("after nextUpdate", x509::ocsp_check_response(r, about, ca, r.next_update) == x509::ERR_EXPIRED);
                }
                var bad: u8[>..] = [];
                bad.append(der);
                bad[bad.len - 20] ^= 1;
                let rb, eb = x509::ocsp_parse_response(bad);
                check("changed", eb != x509::OK || x509::ocsp_check_response(rb, about, ca, now) != x509::OK ||
                      bad.len != der.len);
            }
            // Made again here: the same bytes, when the signature is
            // deterministic (RSA PKCS #1 v1.5; not Go's random ECDSA).
            if signer != "noeku" {
                let responder = load(signer);
                let key, okk = x509::parse_private_key(field("key", signer));
                var t = x509::ocsp_template(status, about.der[about.serial.off..about.serial.end], num(w[6]));
                t.hash = num(w[5]);
                t.next_update = num(w[7]);
                t.revoked_at = num(w[8]);
                t.reason = if num(w[9]) < 0 { 0 } else { num(w[9]) };
                let mine, em = x509::ocsp_create_response(ca, responder, key, t, num(w[11]), w[10] == "true");
                check("made here", okk && em == x509::OK && mine == der);
            }
        } else if w[0] == "error" {
            let st = num(w[1]);
            let der = unhex(w[2]);
            check("error response", x509::ocsp_error_response(st) == der);
            let r, e = x509::ocsp_parse_response(der);
            let leaf = load("leaf");
            check("error parsed", e == x509::OK && r.response_status == st &&
                  x509::ocsp_check_response(r, leaf, ca, now) == x509::ERR_REVOCATION_UNKNOWN);
        }
    }
    let junk, ej = x509::ocsp_parse_response("\x30\x03\x0a\x01\x07");
    check("status 7", ej == x509::ERR_MALFORMED);
    let id, okr = x509::ocsp_parse_request("\x30\x00");
    check("empty request", !okr);
    print("ocsp vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
