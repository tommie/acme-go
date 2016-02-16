package protocol

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/square/go-jose"
)

func TestHTTPClientGet(t *testing.T) {
	hts := newFakeHTTPServer()
	defer hts.Close()

	var d Directory
	_, err := NewHTTPClient(nil, nil).Get(hts.URL, JSON, &d)
	if err != nil {
		t.Fatalf("Get(%q) failed: %v", hts.URL, err)
	}
}

func TestHTTPClientHead(t *testing.T) {
	hts := newFakeHTTPServer()
	defer hts.Close()

	_, err := NewHTTPClient(nil, nil).Head(hts.URL)
	if err != nil {
		t.Fatalf("Head(%q) failed: %v", hts.URL, err)
	}
}

func TestHTTPClientPost(t *testing.T) {
	hts := newFakeHTTPServer()
	defer hts.Close()

	s, err := jose.NewSigner(jose.RS256, testJWK.Key)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	c := NewHTTPClient(nil, s)
	c.nonces.add("hello world")

	in := Registration{
		Resource: ResourceNewReg,
	}
	var got Registration
	_, err = c.Post(hts.URL+"/new-registration", JSON, &in, &got)
	if err != nil {
		t.Fatalf("Post(%q) failed: %v", hts.URL, err)
	}

	if !reflect.DeepEqual(got, in) {
		t.Errorf("Post(%q): got %+v, want %+v", hts.URL, got, in)
	}
}

func TestHTTPClientProblem(t *testing.T) {
	hts := newFakeHTTPServer()
	defer hts.Close()

	_, err := NewHTTPClient(nil, nil).Get(hts.URL+"/new-authz", JSON, nil)
	if err == nil {
		t.Fatalf("Get(%q) got success, want server error", hts.URL+"/new-authz")
	}
	if want := "mock error detail (401 urn:acme:error:unauthorized)"; !strings.HasSuffix(err.Error(), want) {
		t.Fatalf("Get(%q) failed: got %v, want suffix %q", hts.URL+"/new-authz", err, want)
	}
}

func newFakeHTTPServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		switch r.URL.Path {
		case "/":
			w.Header().Set(contentTypeHeader, JSON)
			json.NewEncoder(w).Encode(&Directory{})

		case "/new-registration":
			bs, err := ioutil.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			jws, err := jose.ParseSigned(string(bs))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			bs, err = jws.Verify(testPublicKey)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set(contentTypeHeader, r.Header.Get(contentTypeHeader))
			if _, err := w.Write(bs); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case "/new-authz":
			w.Header().Set(contentTypeHeader, ProblemJSON)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(&Problem{
				Type:   Unauthorized,
				Title:  "mock error",
				Detail: "mock error detail",
			})

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}