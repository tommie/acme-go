package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/square/go-jose"
)

func TestWriteError(t *testing.T) {
	rw := httptest.NewRecorder()
	writeError(rw, fmt.Errorf("mocked failure"))

	if want := http.StatusInternalServerError; rw.Code != want {
		t.Errorf("writeError code: got %v, want %v", rw.Code, want)
	}
	if got, want := rw.HeaderMap.Get(contentTypeHeader), ProblemJSON; got != want {
		t.Errorf("writeError Content-Type: got %v, want %v", got, want)
	}
	want := []byte("{\"type\":\"urn:acme:error:serverInternal\",\"status\":500,\"detail\":\"mocked failure\"}\n")
	if got := rw.Body.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("writeError body: got %v, want %v", got, want)
	}
}

func TestWriteServerError(t *testing.T) {
	rw := httptest.NewRecorder()
	writeError(rw, serverErrorf(http.StatusBadRequest, Malformed, "mocked failure"))

	if want := http.StatusBadRequest; rw.Code != want {
		t.Errorf("writeError code: got %v, want %v", rw.Code, want)
	}
	if got, want := rw.HeaderMap.Get(contentTypeHeader), ProblemJSON; got != want {
		t.Errorf("writeError Content-Type: got %v, want %v", got, want)
	}
	want := []byte("{\"type\":\"urn:acme:error:malformed\",\"status\":400,\"detail\":\"mocked failure\"}\n")
	if got := rw.Body.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("writeError body: got %v, want %v", got, want)
	}
}

func TestWriteResponseGet(t *testing.T) {
	tsts := []struct {
		Name  string
		Req   *http.Request
		Resp  interface{}
		HResp HTTPResponse
		Err   error

		ExpAccept     string
		ExpStatusCode int
		ExpHeader     http.Header
		ExpBody       []byte
	}{
		{
			Name:  "no body",
			Req:   &http.Request{Method: "GET", Header: http.Header{acceptHeader: []string{PKIXCert}}},
			Resp:  nil,
			HResp: HTTPResponse{},

			ExpAccept:     PKIXCert,
			ExpStatusCode: http.StatusOK,
			ExpHeader:     http.Header{},
			ExpBody:       nil,
		},
		{
			Name:  "bytes resp",
			Req:   &http.Request{Method: "GET", Header: http.Header{acceptHeader: []string{PKIXCert}}},
			Resp:  []byte{1, 2, 3, 4},
			HResp: HTTPResponse{},

			ExpAccept:     PKIXCert,
			ExpStatusCode: http.StatusOK,
			ExpHeader:     http.Header{contentTypeHeader: []string{PKIXCert}},
			ExpBody:       []byte{1, 2, 3, 4},
		},
		{
			Name:  "status code",
			Req:   &http.Request{Method: "GET", Header: http.Header{acceptHeader: []string{PKIXCert}}},
			Resp:  []byte{1, 2, 3, 4},
			HResp: HTTPResponse{StatusCode: 999},

			ExpAccept:     PKIXCert,
			ExpStatusCode: 999,
			ExpHeader:     http.Header{contentTypeHeader: []string{PKIXCert}},
			ExpBody:       []byte{1, 2, 3, 4},
		},
		{
			Name:  "header",
			Req:   &http.Request{Method: "GET", Header: http.Header{acceptHeader: []string{PKIXCert}}},
			Resp:  []byte{1, 2, 3, 4},
			HResp: HTTPResponse{Header: http.Header{"X-Test": []string{"hello"}}},

			ExpAccept:     PKIXCert,
			ExpStatusCode: http.StatusOK,
			ExpHeader:     http.Header{contentTypeHeader: []string{PKIXCert}, "X-Test": []string{"hello"}},
			ExpBody:       []byte{1, 2, 3, 4},
		},
		{
			Name:  "encodeBody fails",
			Req:   &http.Request{Method: "GET", Header: http.Header{acceptHeader: []string{PKIXCert}}},
			Resp:  &Registration{},
			HResp: HTTPResponse{},

			ExpAccept:     PKIXCert,
			ExpStatusCode: http.StatusInternalServerError,
			ExpHeader:     http.Header{contentTypeHeader: []string{ProblemJSON}},
			ExpBody:       []byte("{\"type\":\"urn:acme:error:serverInternal\",\"status\":500,\"detail\":\"expected input to be a []byte, got *protocol.Registration\"}\n"),
		},
	}

	for _, tst := range tsts {
		rw := httptest.NewRecorder()
		writeResponse(rw, tst.Req, tst.Resp, &tst.HResp, nil)
		if rw.Code != tst.ExpStatusCode {
			t.Errorf("[%s] writeResponse code: got %v, want %v", tst.Name, rw.Code, tst.ExpStatusCode)
		}
		for k, v := range tst.ExpHeader {
			if !reflect.DeepEqual(rw.HeaderMap[k], v) {
				t.Errorf("[%s] writeResponse header[%q]: got %v, want %v", tst.Name, k, rw.HeaderMap, tst.ExpHeader)
				break
			}
		}
		if got := rw.Body.Bytes(); !bytes.Equal(got, tst.ExpBody) {
			t.Errorf("[%s] writeResponse body: got %v, want %v", tst.Name, got, tst.ExpBody)
		}
	}
}

func TestWriteResponseHead(t *testing.T) {
	ns := newFakeNonceSource()
	rw := httptest.NewRecorder()
	req := &http.Request{Method: "HEAD"}
	writeResponse(rw, req, nil, &HTTPResponse{}, ns)
	if want := http.StatusOK; rw.Code != want {
		t.Errorf("writeResponse code: got %v, want %v", rw.Code, want)
	}
	if want := "0"; rw.HeaderMap.Get(ReplayNonce) != want {
		t.Errorf("writeResponse ReplayNonce: got %q, want %q", rw.HeaderMap.Get(ReplayNonce), want)
	}
}

func TestWriteResponsePost(t *testing.T) {
	ns := newFakeNonceSource()
	rw := httptest.NewRecorder()

	req := &http.Request{
		Method: "POST",
		Header: http.Header{acceptHeader: []string{PKIXCert}},
	}
	writeResponse(rw, req, nil, &HTTPResponse{}, ns)
	if want := http.StatusOK; rw.Code != want {
		t.Errorf("writeResponse code: got %v, want %v", rw.Code, want)
	}
	if want := "0"; rw.HeaderMap.Get(ReplayNonce) != want {
		t.Errorf("writeResponse ReplayNonce: got %q, want %q", rw.HeaderMap.Get(ReplayNonce), want)
	}
}

func TestEncodeBody(t *testing.T) {
	tsts := []struct {
		Name string
		Type string
		In   interface{}

		ExpErr error
		Exp    []byte
	}{
		{
			Name: "json",
			Type: JSON,
			In:   &Registration{Resource: ResourceNewReg},

			Exp: []byte("{\"resource\":\"new-reg\"}\n"),
		},
		{
			Name: "problem",
			Type: ProblemJSON,
			In:   &Problem{Type: "hello", Detail: "world"},

			Exp: []byte("{\"type\":\"hello\",\"detail\":\"world\"}\n"),
		},
		{
			Name: "pkixcert",
			Type: PKIXCert,
			In:   []byte{1, 2, 3, 4},

			Exp: []byte{1, 2, 3, 4},
		},
		{
			Name: "invalid",
			Type: "",

			ExpErr: fmt.Errorf("unhandled "),
		},
	}

	for _, tst := range tsts {
		var buf bytes.Buffer
		err := encodeBody(&buf, tst.Type, tst.In)
		if err != nil {
			if !strings.HasPrefix(err.Error(), tst.ExpErr.Error()) {
				t.Errorf("[%s] encodeBody err: got %q, want prefix %q", tst.Name, err, tst.ExpErr)
				continue
			}
		} else if !bytes.Equal(buf.Bytes(), tst.Exp) {
			t.Errorf("[%s] encodeBody: got %v, want %v", tst.Name, buf.Bytes(), tst.Exp)
		}
	}
}

func TestReadRequest(t *testing.T) {
	ns := newFakeNonceSource()
	sig, err := jose.NewSigner(jose.RS256, testJWK)
	if err != nil {
		t.Fatalf("jose.NewSigner failed: %v", err)
	}
	sig.SetNonceSource(ns)
	signed, err := signJSON(sig, &Registration{Resource: ResourceNewReg})
	if err != nil {
		t.Fatalf("signJSON failed: %v", err)
	}
	bs, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("json.Marshal(%v) failed: %v", signed, err)
	}

	req := &http.Request{
		Method: "POST",
		Header: http.Header{acceptHeader: []string{PKIXCert}, contentTypeHeader: []string{JSON}},
		Body:   ioutil.NopCloser(bytes.NewReader(bs)),
	}
	var reg Registration
	key, err := readRequest(&reg, req, ns)
	if err != nil {
		t.Fatalf("readRequest failed: %v", err)
	}
	if key == nil {
		t.Fatalf("readRequest key: got %v, want non-nil", err)
	}
	if reg.Resource != ResourceNewReg {
		t.Fatalf("readRequest reg.Resource: got %v, want non-nil", reg.Resource)
	}
}

type fakeNonceSource struct {
	next   int
	unseen map[string]bool
}

func newFakeNonceSource() *fakeNonceSource {
	return &fakeNonceSource{unseen: map[string]bool{}}
}

func (ns *fakeNonceSource) Nonce() (string, error) {
	n := strconv.Itoa(ns.next)
	ns.unseen[n] = true
	ns.next++
	return n, nil
}

func (ns *fakeNonceSource) Verify(n string) error {
	if ns.unseen[n] {
		delete(ns.unseen, n)
		return nil
	}
	return fmt.Errorf("invalid nonce")
}
