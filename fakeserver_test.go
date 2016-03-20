package acme

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"

	"github.com/square/go-jose"
	"github.com/tommie/acme-go/protocol"
)

const (
	contentTypeHeader = "Content-Type"
)

type fakeACMEServer struct {
	mux       *http.ServeMux
	baseURL   string
	nextNonce int64
}

func newFakeACMEServer() (*fakeACMEServer, *httptest.Server) {
	as := &fakeACMEServer{
		mux: http.NewServeMux(),
	}

	as.mux.HandleFunc("/", as.directory)
	as.mux.HandleFunc("/new-registration", as.newRegistration)
	as.mux.HandleFunc("/new-authz", as.newAuthz)
	hts := httptest.NewServer(as.mux)
	as.baseURL = hts.URL

	return as, hts
}

func (s *fakeACMEServer) directory(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		s.respond(w, http.StatusOK, protocol.JSON, &protocol.Directory{
			NewReg: s.baseURL + "/new-registration",
		})

	case "HEAD":
		s.setNonce(w)

	default:
		http.Error(w, r.Method, http.StatusMethodNotAllowed)
	}
}

func (s *fakeACMEServer) newRegistration(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "HEAD":
		s.setNonce(w)

	case "POST":
		var reg protocol.Registration
		if err := s.decodeBody(&reg, r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set(locationHeader, s.baseURL+"/reg/1")
		s.setNonce(w)
		s.respond(w, http.StatusCreated, protocol.JSON, &reg)

	default:
		http.Error(w, r.Method, http.StatusMethodNotAllowed)
	}
}

func (s *fakeACMEServer) newAuthz(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		p := protocol.Problem{
			Type:   protocol.Unauthorized,
			Title:  "mock error",
			Detail: "mock error detail",
		}
		s.setNonce(w)
		s.respond(w, http.StatusUnauthorized, protocol.ProblemJSON, &p)

	default:
		http.Error(w, r.Method, http.StatusMethodNotAllowed)
	}
}

func (s *fakeACMEServer) setNonce(w http.ResponseWriter) {
	w.Header().Set(protocol.ReplayNonce, strconv.FormatInt(s.nextNonce, 10))
	s.nextNonce++
}

func (s *fakeACMEServer) decodeBody(out interface{}, r *http.Request) error {
	bs, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	jws, err := jose.ParseSigned(string(bs))
	if err != nil {
		return err
	}

	bs, err = jws.Verify(testPublicKey)
	if err != nil {
		return err
	}

	return decodeBody(out, r.Header.Get(contentTypeHeader), bytes.NewReader(bs))
}

func (s *fakeACMEServer) respond(w http.ResponseWriter, status int, contentType string, body interface{}) {
	w.Header().Set(contentTypeHeader, contentType)
	w.WriteHeader(status)

	r, err := encodeBody(contentType, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = io.Copy(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// decodeBody decodes an HTTP body as a specific contentType.
func decodeBody(out interface{}, contentType string, r io.Reader) error {
	switch contentType {
	case protocol.JSON, protocol.ProblemJSON:
		return json.NewDecoder(r).Decode(out)

	case protocol.PKIXCert:
		bs, err := ioutil.ReadAll(r)
		if err != nil {
			return err
		}
		bsout, ok := out.(*[]byte)
		if !ok {
			return fmt.Errorf("expected input to be a *[]byte, got %T", out)
		}
		*bsout = bs
		return err

	default:
		return fmt.Errorf("unhandled content type: %q", contentType)
	}
}

// encodeBody encodes an HTTP body as specified by the contentType.
func encodeBody(contentType string, in interface{}) (io.Reader, error) {
	switch contentType {
	case protocol.JSON, protocol.ProblemJSON:
		b := bytes.NewBuffer(nil)
		if err := json.NewEncoder(b).Encode(in); err != nil {
			return nil, err
		}
		return b, nil

	case protocol.PKIXCert:
		bsin, ok := in.(*[]byte)
		if !ok {
			return nil, fmt.Errorf("expected input to be a *[]byte, got %T", in)
		}
		return bytes.NewReader(*bsin), nil

	default:
		return nil, fmt.Errorf("unhandled content type: %q", contentType)
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
