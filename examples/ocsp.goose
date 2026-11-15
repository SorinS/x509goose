// OCSP (RFC 6960), client and responder in one process: the client asks
// about a certificate; the CA answers "good" for one and "revoked" for
// another, signed with its own key; then a delegated responder (a
// certificate with id-kp-OCSPSigning) answers instead of the CA. The
// client checks each answer: issuer, signer, dates and status. Error
// responses ("try later") give "unknown".
//
//   goose examples/ocsp.goose
import std;
import os;
import x509 from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509.keys;
import x509.create;
import x509.verify;
import x509.crl;
import x509.ocsp;

let DAY: i64 = 86400;

fn fail(what: const u8[:], e: i64) { print("ocsp: ", what, ": ", x509::error_text(e)); exit(1); }

fn issue(subject: const u8[:], eku: u32, ca: const u8[:], ca_key: const x509::PrivateKey&, now: i64) -> u8[>..] {
    let k = x509::generate_key(x509::KEY_ED25519);
    var t, ok = x509::template(subject, now - DAY, now + 90 * DAY);
    t.key_usage = x509::KU_DIGITAL_SIGNATURE;
    t.ext_key_usage = eku;
    let der, e = x509::create_certificate(t, x509::marshal_public_key(k), ca, ca_key);
    guard ok && e == x509::OK else { fail(subject, e); }
    return der;
}

// The responder's side: read the request, look the serial up, answer.
fn respond(req: const u8[:], revoked_serial: const u8[:], ca: const x509::Cert&, signer: const x509::Cert&,
           key: const x509::PrivateKey&, now: i64) -> u8[>..] {
    let id, ok = x509::ocsp_parse_request(req);
    if !ok { return x509::ocsp_error_response(x509::OCSP_MALFORMED_REQUEST); }
    var t = x509::ocsp_template(x509::OCSP_GOOD, id.serial, now - 60);
    t.next_update = now + DAY;
    if id.serial[..] == revoked_serial {
        t.status = x509::OCSP_REVOKED;
        t.revoked_at = now - 3600;
        t.reason = x509::REASON_KEY_COMPROMISE;
    }
    // A delegated responder sends its certificate along.
    let delegated = signer.der != ca.der;
    let der, e = x509::ocsp_create_response(ca, signer, key, t, now, delegated);
    guard e == x509::OK else { fail("ocsp_create_response", e); }
    return der;
}

// The client asks about c; the CA answers with its own key.
fn ask(c: const x509::Cert&, want: i64, ca: const x509::Cert&, ca_key: const x509::PrivateKey&,
       lost_serial: const u8[:], now: i64) {
    let req = x509::ocsp_create_request(c, ca);
    let der = respond(req, lost_serial, ca, ca, ca_key, now);
    let r, er = x509::ocsp_parse_response(der);
    guard er == x509::OK else { fail("ocsp_parse_response", er); }
    let st = x509::ocsp_check_response(r, c, ca, now);
    print(x509::subject_text(c), ": request ", req.len, " bytes, response ", der.len, " bytes, signed by the CA: ",
          if st == x509::OK { "good" } else { x509::error_text(st) });
    guard st == want else { fail("unexpected status", st); }
    if st == x509::ERR_REVOKED { print("  revoked ", now - r.revoked_at, " s ago, reason ", r.reason); }
}

fn main() {
    let now = time() as i64;
    let ca_key = x509::generate_key(x509::KEY_EC_P256);
    var ct, okc = x509::template("CN=Example CA,O=Example", now - DAY, now + 365 * DAY);
    ct.is_ca = true;
    ct.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    let ca_der, eca = x509::create_certificate(ct, x509::marshal_public_key(ca_key), "", ca_key);
    guard okc && eca == x509::OK else { fail("CA", eca); }
    let ca, e0 = x509::parse(ca_der);
    let good, e1 = x509::parse(issue("CN=good.example.com", x509::EKU_SERVER_AUTH, ca_der, ca_key, now));
    let lost, e2 = x509::parse(issue("CN=lost.example.com", x509::EKU_SERVER_AUTH, ca_der, ca_key, now));
    let lost_serial = lost.der[lost.serial.off..lost.serial.end];

    // The client: a request per certificate (SHA-1 CertID, as most
    // responders expect), sent by HTTP POST in real life.
    ask(good, x509::OK, ca, ca_key, lost_serial, now);
    ask(lost, x509::ERR_REVOKED, ca, ca_key, lost_serial, now);

    // A delegated responder: the CA keeps its key offline and certifies a
    // responder key for OCSP signing only.
    let rkey = x509::generate_key(x509::KEY_EC_P256);
    var rt, okr = x509::template("CN=Example OCSP Responder", now - DAY, now + 30 * DAY);
    rt.key_usage = x509::KU_DIGITAL_SIGNATURE;
    rt.ext_key_usage = x509::EKU_OCSP_SIGNING;
    let rder, erc = x509::create_certificate(rt, x509::marshal_public_key(rkey), ca_der, ca_key);
    guard okr && erc == x509::OK else { fail("responder", erc); }
    let responder, e3 = x509::parse(rder);
    let der = respond(x509::ocsp_create_request(good, ca, 256), lost_serial, ca, responder, rkey, now);
    let r, er = x509::ocsp_parse_response(der);
    let st = x509::ocsp_check_response(r, good, ca, now);
    print("good.example.com via the delegated responder (SHA-256 CertID): ", x509::error_text(st));
    guard er == x509::OK && r.has_cert && st == x509::OK else { fail("delegated", st); }
    // Too late: the answer is past its nextUpdate.
    let stale = x509::ocsp_check_response(r, good, ca, now + 2 * DAY);
    guard stale == x509::ERR_EXPIRED else { fail("stale response", stale); }

    // An answer about another certificate does not count for this one.
    guard x509::ocsp_check_response(r, lost, ca, now) != x509::OK else { print("ocsp: wrong certificate"); exit(1); }

    // Unsuccessful responses carry no status: unknown.
    let busy, eb = x509::ocsp_parse_response(x509::ocsp_error_response(x509::OCSP_TRY_LATER));
    let sb = x509::ocsp_check_response(busy, good, ca, now);
    print("tryLater response: ", x509::error_text(sb));
    guard sb == x509::ERR_REVOCATION_UNKNOWN else { fail("error response", sb); }
}
