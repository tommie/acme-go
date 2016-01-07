package acme

import (
	"crypto/rsa"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/square/go-jose"
	"github.com/tommie/acme-go/protocol"
)

func TestHTTPClientGet(t *testing.T) {
	_, hts := newFakeACMEServer()
	defer hts.Close()

	var d protocol.Directory
	_, err := newHTTPClient(nil).Get(hts.URL, protocol.JSON, &d)
	if err != nil {
		t.Fatalf("Get(%q) failed: %v", hts.URL, err)
	}
}

func TestHTTPClientHead(t *testing.T) {
	_, hts := newFakeACMEServer()
	defer hts.Close()

	_, err := newHTTPClient(nil).Head(hts.URL)
	if err != nil {
		t.Fatalf("Head(%q) failed: %v", hts.URL, err)
	}
}

func TestHTTPClientPost(t *testing.T) {
	_, hts := newFakeACMEServer()
	defer hts.Close()

	s, err := jose.NewSigner(jose.RS256, testJWK.Key)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	c := newHTTPClient(s)
	c.nonces.add("hello world")

	in := protocol.Registration{
		Resource: protocol.ResourceNewReg,
	}
	var got protocol.Registration
	_, err = c.Post(hts.URL+"/new-registration", protocol.JSON, &in, &got)
	if err != nil {
		t.Fatalf("Post(%q) failed: %v", hts.URL, err)
	}

	if !reflect.DeepEqual(got, in) {
		t.Errorf("Post(%q): got %+v, want %+v", hts.URL, got, in)
	}
}

var (
	// testJWK is a JsonWebKey used for tests. Generated by protocol.mustGenerateTestJWK.
	testJWK = mustUnmarshalJWK(`{
	"kty": "RSA",
	"n": "1-OrKVWRL2mjMk8CQS4aoX0vY2RHjjPQbE-CwtSnXDmw9pe1NB3xc9LBrB_pWpjrJKzyJm8PEz4YGDNVC8UzCw",
	"e": "AQAB",
	"d": "vYhi_CbjD3zuiXxTvmV7e8srj1a6e12B3ZTwd5u6Unu13MqiceywGjXP98z18uCrAYgxyHHGQY6X7Ahfm2riAQ",
	"p": "23IPuW88sFRlPOlJ_OUWjQKE7DOXCFyUbeWxD8unk18",
	"q": "-9n1DN65zlVdGXzwxbt1tIxt2Jj8aQMrr-qa_i-Ni9U"
}`)
	// testPublicKey is the raw crypto.PublicKey part of testJWK.
	testPublicKey = testJWK.Key.(*rsa.PrivateKey).Public()
)

// mustUnmarshalJWK takes a JSON string and unmarshals the key. Panics on error.
func mustUnmarshalJWK(s string) *jose.JsonWebKey {
	ret := &jose.JsonWebKey{}
	if err := json.Unmarshal([]byte(s), ret); err != nil {
		panic(err)
	}
	return ret
}
