package acme

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"

	"github.com/square/go-jose"
	"github.com/tommie/acme-go/protocol"
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
		w.Header().Set("Location", s.baseURL+"/reg/1")
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
			Type: protocol.Unauthorized,
			Title: "mock error",
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
