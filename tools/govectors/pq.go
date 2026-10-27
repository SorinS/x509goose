// The Go part of test/vectors/pq.txt: an ML-DSA hierarchy made by
// crypto/x509 (ML-DSA-65 root, ML-DSA-44 intermediate, leaves on
// ML-DSA-87 and P-256 keys) with its path cases, and Go's PKCS #8 and
// SubjectPublicKeyInfo of keys from fixed seeds.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func pqCert(id, name string, serial int64, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer,
	ca bool) *x509.Certificate {
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name, Organization: []string{"Goose PQ"}},
		NotBefore:    t0.Add(-24 * time.Hour),
		NotAfter:     t0.Add(365 * 24 * time.Hour),
	}
	if ca {
		tpl.IsCA = true
		tpl.BasicConstraintsValid = true
		tpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tpl.KeyUsage = x509.KeyUsageDigitalSignature
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.DNSNames = []string{"pq.example.com"}
	}
	if parent == nil {
		parent = tpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	fmt.Printf("cert %s %x\n", id, der)
	return c
}

func mlKey(p mldsa.Parameters) *mldsa.PrivateKey {
	k, err := mldsa.GenerateKey(p)
	if err != nil {
		panic(err)
	}
	return k
}

func pqMain() {
	rootKey := mlKey(mldsa.MLDSA65())
	root := pqCert("go_root", "Goose Go ML-DSA Root", 1, rootKey.Public(), nil, rootKey, true)
	intKey := mlKey(mldsa.MLDSA44())
	inter := pqCert("go_int", "Goose Go ML-DSA Issuing", 2, intKey.Public(), root, rootKey, true)
	leafKey := mlKey(mldsa.MLDSA87())
	leaf := pqCert("go_leaf", "pq.example.com", 3, leafKey.Public(), inter, intKey, false)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecLeaf := pqCert("go_leaf_ec", "pq.example.com", 4, ecKey.Public(), inter, intKey, false)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inters := x509.NewCertPool()
	inters.AddCert(inter)
	for _, l := range []*x509.Certificate{leaf, ecLeaf} {
		if _, err := l.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: "pq.example.com",
			CurrentTime: t0}); err != nil {
			panic(err)
		}
	}
	fmt.Printf("case go_ml_dsa_87_leaf go_leaf go_int go_root %d pq.example.com 0\n", t0.Unix())
	fmt.Printf("case go_p256_leaf go_leaf_ec go_int go_root %d pq.example.com 0\n", t0.Unix())
	fmt.Printf("case go_wrong_host go_leaf go_int go_root %d other.example.com 11\n", t0.Unix())
	for i, p := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		seed := make([]byte, 32)
		for j := range seed {
			seed[j] = byte(0x40*i + j)
		}
		k, err := mldsa.NewPrivateKey(p, seed)
		if err != nil {
			panic(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			panic(err)
		}
		spki, err := x509.MarshalPKIXPublicKey(k.Public())
		if err != nil {
			panic(err)
		}
		fmt.Printf("gokey %d %x %x %x\n", []int{44, 65, 87}[i], seed, der, spki)
	}
}

func readPEM(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		panic("no PEM in " + path)
	}
	return blk.Bytes
}

// checkMain verifies the ML-DSA leaves tools/make_pki.goose made under
// its ML-DSA root, and parses their PKCS #8 keys, whose public keys must
// be the certificates'.
func checkMain(dir string) {
	root, err := x509.ParseCertificate(readPEM(filepath.Join(dir, "pq_root.pem")))
	if err != nil {
		panic(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	for _, name := range []string{"leaf_mldsa44", "leaf_mldsa87"} {
		leaf, err := x509.ParseCertificate(readPEM(filepath.Join(dir, name+".pem")))
		if err != nil {
			panic(err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "www.example.com"}); err != nil {
			panic(fmt.Sprint(name, ": ", err))
		}
		k, err := x509.ParsePKCS8PrivateKey(readPEM(filepath.Join(dir, name+".key")))
		if err != nil {
			panic(err)
		}
		if !leaf.PublicKey.(*mldsa.PublicKey).Equal(k.(*mldsa.PrivateKey).Public()) {
			panic(name + ": key does not match")
		}
	}
	csr, err := x509.ParseCertificateRequest(readPEM(filepath.Join(dir, "csr_mldsa.pem")))
	if err != nil || csr.CheckSignature() != nil {
		panic(fmt.Sprint("csr: ", err))
	}
	crl, err := x509.ParseRevocationList(readPEM(filepath.Join(dir, "crl_pq.pem")))
	if err != nil || crl.CheckSignatureFrom(root) != nil {
		panic(fmt.Sprint("crl: ", err))
	}
	fmt.Println("ok")
}
