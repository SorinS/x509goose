// OCSP vectors from Go's golang.org/x/crypto/ocsp: a CA, certificates it
// issued, a delegated responder with and without id-kp-OCSPSigning, and
// requests and responses made by Go. Go's CreateResponse signs with RSA
// or ECDSA only, so the CA and responders have RSA keys (one ECDSA),
// fresh each run, and the certificates the responses are about Ed25519
// keys from fixed seeds; producedAt is the minute Go ran, read back from
// each response.
//
//	cd scripts/govectors && GOFLAGS=-mod=mod GOPROXY=off go run . > ../../test/vectors/ocsp.txt
//
// With the argument `pq` it prints instead the Go part of pq.txt (see
// pq.go and scripts/pq_vectors.py); with `check <dir>` it checks what
// tools/make_pki.goose made (for scripts/check_created.py).
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"time"

	"golang.org/x/crypto/ocsp"
)

var t0 = time.Unix(1793000000, 0).UTC() // 2026-10-26, as the other vectors

func seedKey(b byte) ed25519.PrivateKey {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = b + byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func cert(id, name string, serial int64, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer, ca bool,
	eku []x509.ExtKeyUsage) *x509.Certificate {
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name, Organization: []string{"Goose OCSP"}},
		NotBefore:    t0.Add(-24 * time.Hour),
		NotAfter:     t0.Add(365 * 24 * time.Hour),
		ExtKeyUsage:  eku,
	}
	if ca {
		tpl.IsCA = true
		tpl.BasicConstraintsValid = true
		tpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	} else {
		tpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	if parent == nil {
		parent = tpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
	if err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(der)
	fmt.Printf("cert %s %x\n", id, der)
	return c
}

func rsaKey() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}

func key(name string, k crypto.Signer) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		panic(err)
	}
	fmt.Printf("key %s %x\n", name, der)
}

func hashID(h crypto.Hash) int {
	return map[crypto.Hash]int{crypto.SHA1: 160, crypto.SHA256: 256, crypto.SHA384: 384, crypto.SHA512: 512}[h]
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return -1
	}
	return t.Unix()
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "pq" {
		pqMain()
		return
	}
	if len(os.Args) > 2 && os.Args[1] == "check" {
		checkMain(os.Args[2])
		return
	}
	caKey := rsaKey()
	ca := cert("ca", "Goose OCSP CA", 1, caKey.Public(), nil, caKey, true, nil)
	otherKey := rsaKey()
	other := cert("other", "Other CA", 2, otherKey.Public(), nil, otherKey, true, nil)
	_ = other
	leaf := cert("leaf", "leaf.example", 0x1234567890, seedKey(3).Public(), ca, caKey, false, nil)
	leaf2 := cert("leaf2", "leaf2.example", 77, seedKey(4).Public(), ca, caKey, false, nil)
	rk := rsaKey()
	responder := cert("responder", "Goose OCSP Responder", 5, rk.Public(), ca, caKey, false, []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning})
	nokuKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	noeku := cert("noeku", "Not a Responder", 6, nokuKey.Public(), ca, caKey, false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	key("ca", caKey)
	key("other", otherKey)
	key("responder", rk)
	key("noeku", nokuKey)

	for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		der, err := ocsp.CreateRequest(leaf, ca, &ocsp.RequestOptions{Hash: h})
		if err != nil {
			panic(err)
		}
		fmt.Printf("request %d %x\n", hashID(h), der)
	}

	type kase struct {
		name     string
		signer   string
		subject  *x509.Certificate // the certificate the response is about
		resp     *x509.Certificate // responderCert
		priv     crypto.Signer
		include  bool
		status   int
		reason   int
		next     time.Duration
		hash     crypto.Hash
	}
	cases := []kase{
		{"good", "ca", leaf, ca, caKey, false, ocsp.Good, 0, 7 * 24 * time.Hour, crypto.SHA1},
		{"revoked", "ca", leaf, ca, caKey, false, ocsp.Revoked, ocsp.KeyCompromise, 0, crypto.SHA1},
		{"revoked-unspecified", "ca", leaf, ca, caKey, false, ocsp.Revoked, ocsp.Unspecified, 24 * time.Hour, crypto.SHA256},
		{"unknown", "ca", leaf, ca, caKey, false, ocsp.Unknown, 0, time.Hour, crypto.SHA1},
		{"delegated", "responder", leaf, responder, rk, true, ocsp.Good, 0, 24 * time.Hour, crypto.SHA256},
		{"delegated-revoked", "responder", leaf2, responder, rk, true, ocsp.Revoked, ocsp.Superseded, 24 * time.Hour, crypto.SHA384},
		{"no-eku", "noeku", leaf, noeku, nokuKey, true, ocsp.Good, 0, 24 * time.Hour, crypto.SHA1},
		{"other-ca", "other", leaf, other, otherKey, false, ocsp.Good, 0, 24 * time.Hour, crypto.SHA1},
		{"other-leaf", "ca", leaf2, ca, caKey, false, ocsp.Good, 0, 24 * time.Hour, crypto.SHA512},
	}
	for _, k := range cases {
		tpl := ocsp.Response{
			Status:       k.status,
			SerialNumber: k.subject.SerialNumber,
			ThisUpdate:   t0.Add(-time.Hour),
			IssuerHash:   k.hash,
		}
		if k.next != 0 {
			tpl.NextUpdate = t0.Add(k.next)
		}
		if k.status == ocsp.Revoked {
			tpl.RevokedAt = t0.Add(-48 * time.Hour)
			tpl.RevocationReason = k.reason
		}
		if k.include {
			tpl.Certificate = k.resp
		}
		der, err := ocsp.CreateResponse(ca, k.resp, tpl, k.priv)
		if err != nil {
			panic(err)
		}
		parsed, err := ocsp.ParseResponse(der, nil)
		if err != nil {
			panic(err)
		}
		reason := -1
		if k.status == ocsp.Revoked && k.reason != 0 {
			reason = k.reason
		}
		about := "leaf"
		if k.subject == leaf2 {
			about = "leaf2"
		}
		fmt.Printf("response %s %s %s %d %d %d %d %d %d %t %d %s\n", k.name, k.signer, about, k.status, hashID(k.hash),
			unix(tpl.ThisUpdate), unix(tpl.NextUpdate), unix(tpl.RevokedAt), reason, k.include,
			parsed.ProducedAt.Unix(), hex.EncodeToString(der))
	}
	for _, e := range [][]byte{ocsp.MalformedRequestErrorResponse, ocsp.InternalErrorErrorResponse,
		ocsp.TryLaterErrorResponse, ocsp.SigRequredErrorResponse, ocsp.UnauthorizedErrorResponse} {
		fmt.Printf("error %d %x\n", e[4], e)
	}
}
