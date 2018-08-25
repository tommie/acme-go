package protocol

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"gopkg.in/square/go-jose.v2"
)

func TestHTTPDispatcher(t *testing.T) {
	ns := newFakeNonceSource()
	sig, err := jose.NewSigner(testSigningKey, &jose.SignerOptions{NonceSource: ns, EmbedJWK: true})
	if err != nil {
		t.Fatalf("jose.NewSigner failed: %v", err)
	}
	hs := mockHTTPServer{}
	d := NewHTTPDispatcher(&hs, ns)
	tsts := []struct {
		Req *http.Request
		F   func(http.ResponseWriter, *http.Request)
		N   *int

		ExpCode int
	}{
		{
			Req: &http.Request{
				Method: "GET",
				URL:    &url.URL{Path: AuthzPath},
				Header: http.Header{acceptHeader: []string{JSON}},
			},
			F: d.ServeAuthz,
			N: &hs.NGetAuthz,

			ExpCode: http.StatusOK,
		},
		{
			Req: &http.Request{
				Method: "POST",
				URL:    &url.URL{Path: AuthzPath},
				Header: http.Header{acceptHeader: []string{JSON}, contentTypeHeader: []string{JSON}},
				Body:   mustEncodeRequestBody(&Authorization{}, sig),
			},
			F: d.ServeAuthz,
			N: &hs.NPostAuthz,

			ExpCode: http.StatusOK,
		},
		{
			Req: &http.Request{
				Method: "GET",
				URL:    &url.URL{Path: NewAuthzPath},
				Header: http.Header{acceptHeader: []string{JSON}},
			},
			F: d.ServeNewAuthz,
			N: nil,

			ExpCode: http.StatusMethodNotAllowed,
		},
		{
			Req: &http.Request{
				Method: "POST",
				URL:    &url.URL{Path: NewAuthzPath},
				Header: http.Header{acceptHeader: []string{JSON}, contentTypeHeader: []string{JSON}},
				Body:   mustEncodeRequestBody(&Authorization{}, sig),
			},
			F: d.ServeNewAuthz,
			N: &hs.NPostAuthz,

			ExpCode: http.StatusOK,
		},
		{
			Req: &http.Request{
				Method: "GET",
				URL:    &url.URL{Path: CertPath},
				Header: http.Header{acceptHeader: []string{JSON}},
			},
			F: d.ServeCert,
			N: &hs.NGetCert,

			ExpCode: http.StatusOK,
		},
		{
			Req: &http.Request{
				Method: "POST",
				URL:    &url.URL{Path: CertPath},
				Header: http.Header{acceptHeader: []string{JSON}, contentTypeHeader: []string{JSON}},
				Body:   mustEncodeRequestBody(&Certificate{}, sig),
			},
			F: d.ServeCert,
			N: nil,

			ExpCode: http.StatusMethodNotAllowed,
		},
		{
			Req: &http.Request{
				Method: "GET",
				URL:    &url.URL{Path: NewCertPath},
				Header: http.Header{acceptHeader: []string{JSON}},
			},
			F: d.ServeNewCert,
			N: nil,

			ExpCode: http.StatusMethodNotAllowed,
		},
		{
			Req: &http.Request{
				Method: "POST",
				URL:    &url.URL{Path: NewCertPath},
				Header: http.Header{acceptHeader: []string{PKIXCert}, contentTypeHeader: []string{JSON}},
				Body:   mustEncodeRequestBody(&CertificateIssuance{}, sig),
			},
			F: d.ServeNewCert,
			N: &hs.NPostCertIss,

			ExpCode: http.StatusOK,
		},
		{
			Req: &http.Request{
				Method: "GET",
				URL:    &url.URL{Path: ChallengePath},
				Header: http.Header{acceptHeader: []string{JSON}},
			},
			F: d.ServeChallenge,
			N: nil,

			ExpCode: http.StatusMethodNotAllowed,
		},
		{
			Req: &http.Request{
				Method: "POST",
				URL:    &url.URL{Path: ChallengePath},
				Header: http.Header{acceptHeader: []string{JSON}, contentTypeHeader: []string{JSON}},
				Body:   mustEncodeRequestBody(&GenericResponse{}, sig),
			},
			F: d.ServeChallenge,
			N: &hs.NPostResp,

			ExpCode: http.StatusOK,
		},
		{
			Req: &http.Request{
				Method: "GET",
				URL:    &url.URL{Path: RecoverRegPath},
				Header: http.Header{acceptHeader: []string{JSON}},
			},
			F: d.ServeRecoverReg,
			N: nil,

			ExpCode: http.StatusMethodNotAllowed,
		},
		{
			Req: &http.Request{
				Method: "POST",
				URL:    &url.URL{Path: RecoverRegPath},
				Header: http.Header{acceptHeader: []string{JSON}, contentTypeHeader: []string{JSON}},
				Body:   mustEncodeRequestBody(&Recovery{}, sig),
			},
			F: d.ServeRecoverReg,
			N: &hs.NPostAccRec,

			ExpCode: http.StatusOK,
		},
		{
			Req: &http.Request{
				Method: "GET",
				URL:    &url.URL{Path: RegPath},
				Header: http.Header{acceptHeader: []string{JSON}},
			},
			F: d.ServeReg,
			N: nil,

			ExpCode: http.StatusMethodNotAllowed,
		},
		{
			Req: &http.Request{
				Method: "POST",
				URL:    &url.URL{Path: RegPath},
				Header: http.Header{acceptHeader: []string{JSON}, contentTypeHeader: []string{JSON}},
				Body:   mustEncodeRequestBody(&Registration{}, sig),
			},
			F: d.ServeReg,
			N: &hs.NPostReg,

			ExpCode: http.StatusOK,
		},
		{
			Req: &http.Request{
				Method: "GET",
				URL:    &url.URL{Path: RevokeCertPath},
				Header: http.Header{acceptHeader: []string{JSON}},
			},
			F: d.ServeRevokeCert,
			N: nil,

			ExpCode: http.StatusMethodNotAllowed,
		},
		{
			Req: &http.Request{
				Method: "POST",
				URL:    &url.URL{Path: RevokeCertPath},
				Header: http.Header{contentTypeHeader: []string{JSON}},
				Body:   mustEncodeRequestBody(&Certificate{}, sig),
			},
			F: d.ServeRevokeCert,
			N: &hs.NPostCertRev,

			ExpCode: http.StatusOK,
		},
	}

	for _, tst := range tsts {
		hs = mockHTTPServer{}
		rw := httptest.NewRecorder()
		tst.F(rw, tst.Req)

		if rw.Code != tst.ExpCode {
			t.Errorf("%s %s Code: got %v, want %v (%s)", tst.Req.Method, tst.Req.URL, rw.Code, tst.ExpCode, rw.Body.Bytes())
			continue
		}
		if want := 1; tst.N != nil && *tst.N != want {
			t.Errorf("%s %s N: got %v, want %v", tst.Req.Method, tst.Req.URL, *tst.N, want)
		}
	}
}

func TestHTTPDispatcherServeHead(t *testing.T) {
	ns := newFakeNonceSource()
	d := NewHTTPDispatcher(nil, ns)
	req := &http.Request{
		Method: "HEAD",
	}
	rw := httptest.NewRecorder()
	var nget, npost int
	d.serve(rw, req, "*/*", func() (interface{}, HTTPResponse, error) {
		nget++
		return nil, HTTPResponse{}, nil
	}, nil, func(crypto.PublicKey) (interface{}, HTTPResponse, error) {
		npost++
		return nil, HTTPResponse{}, nil
	})

	if want := http.StatusOK; rw.Code != want {
		t.Fatalf("serve Code: got %v, want %v (%s)", rw.Code, want, rw.Body.Bytes())
	}
	if want := 0; nget != want {
		t.Errorf("serve get: got %v, want %v", nget, want)
	}
	if want := 0; npost != want {
		t.Errorf("serve post: got %v, want %v", npost, want)
	}
	if got, want := rw.HeaderMap.Get(ReplayNonce), "0"; got != want {
		t.Errorf("serve Replay-Nonce: got %q, want %q", got, want)
	}
}

func TestHTTPDispatcherServeGetFails(t *testing.T) {
	ns := newFakeNonceSource()
	d := NewHTTPDispatcher(nil, ns)
	req := &http.Request{
		Method: "GET",
	}
	rw := httptest.NewRecorder()
	var nget, npost int
	d.serve(rw, req, "*/*", func() (interface{}, HTTPResponse, error) {
		nget++
		return nil, HTTPResponse{}, fmt.Errorf("mocked failure")
	}, nil, func(crypto.PublicKey) (interface{}, HTTPResponse, error) {
		npost++
		return nil, HTTPResponse{}, nil
	})

	if want := http.StatusInternalServerError; rw.Code != want {
		t.Fatalf("serve Code: got %v, want %v (%s)", rw.Code, want, rw.Body.Bytes())
	}
	if want := 1; nget != want {
		t.Errorf("serve get: got %v, want %v", nget, want)
	}
	if want := 0; npost != want {
		t.Errorf("serve post: got %v, want %v", npost, want)
	}
}

func TestHTTPDispatcherServePostFails(t *testing.T) {
	ns := newFakeNonceSource()
	sig, err := jose.NewSigner(testSigningKey, &jose.SignerOptions{NonceSource: ns, EmbedJWK: true})
	if err != nil {
		t.Fatalf("jose.NewSigner failed: %v", err)
	}
	d := NewHTTPDispatcher(nil, ns)
	req := &http.Request{
		Method: "POST",
		Header: http.Header{contentTypeHeader: []string{JSON}},
		Body:   mustEncodeRequestBody(&Directory{}, sig),
	}
	rw := httptest.NewRecorder()
	var nget, npost int
	var dir Directory
	d.serve(rw, req, "*/*", func() (interface{}, HTTPResponse, error) {
		nget++
		return nil, HTTPResponse{}, nil
	}, &dir, func(crypto.PublicKey) (interface{}, HTTPResponse, error) {
		npost++
		return nil, HTTPResponse{}, fmt.Errorf("mocked failure")
	})

	if want := http.StatusInternalServerError; rw.Code != want {
		t.Fatalf("serve Code: got %v, want %v (%s)", rw.Code, want, rw.Body.Bytes())
	}
	if want := 0; nget != want {
		t.Errorf("serve get: got %v, want %v", nget, want)
	}
	if want := 1; npost != want {
		t.Errorf("serve post: got %v, want %v", npost, want)
	}
}

func TestHTTPDispatcherServePostInvalidNonce(t *testing.T) {
	ns := newFakeNonceSource()
	sig, err := jose.NewSigner(testSigningKey, &jose.SignerOptions{NonceSource: ns, EmbedJWK: true})
	if err != nil {
		t.Fatalf("jose.NewSigner failed: %v", err)
	}
	d := NewHTTPDispatcher(nil, ns)
	req := &http.Request{
		Method: "POST",
		Header: http.Header{contentTypeHeader: []string{JSON}},
		Body:   mustEncodeRequestBody(&Directory{}, sig),
	}
	ns.Verify("0")
	rw := httptest.NewRecorder()
	var dir Directory
	d.serve(rw, req, "*/*", nil, &dir,
		func(crypto.PublicKey) (interface{}, HTTPResponse, error) {
			return nil, HTTPResponse{}, nil
		})

	if want := http.StatusForbidden; rw.Code != want {
		t.Fatalf("serve Code: got %v, want %v (%s)", rw.Code, want, rw.Body.Bytes())
	}
}

func TestRegisterBoulderHTTP(t *testing.T) {
	root, err := url.Parse("http://acme.example.com/")
	if err != nil {
		t.Fatalf("url.Parse failed: %v", err)
	}
	mux := http.NewServeMux()
	hs := mockHTTPServer{}
	RegisterBoulderHTTP(mux, &hs, nil)

	// Also tests ServeDirectory.
	rw := httptest.NewRecorder()
	req := &http.Request{
		Method: "GET",
		URL:    root.ResolveReference(&url.URL{Path: DirectoryPath}),
		Header: http.Header{acceptHeader: []string{JSON}},
	}
	mux.ServeHTTP(rw, req)

	if want := http.StatusOK; rw.Code != want {
		t.Fatalf("mux.ServeHTTP Code: got %v, want %v", rw.Code, want)
	}
	if got, want := rw.HeaderMap.Get(contentTypeHeader), JSON; got != want {
		t.Errorf("mux.ServeHTTP Content-Type: got %q, want %q", got, want)
	}
}

func mustEncodeRequestBody(data interface{}, sig jose.Signer) io.ReadCloser {
	ret, err := encodeRequestBody(data, sig)
	if err != nil {
		panic(err)
	}
	return ret
}

func encodeRequestBody(data interface{}, sig jose.Signer) (io.ReadCloser, error) {
	signed, err := signJSON(sig, data)
	if err != nil {
		return nil, err
	}

	bs, err := json.Marshal(signed)
	if err != nil {
		return nil, err
	}

	return ioutil.NopCloser(bytes.NewReader(bs)), nil
}

type mockHTTPServer struct {
	NDir         int
	NPostReg     int
	NPostAccRec  int
	NPostAuthz   int
	NGetAuthz    int
	NPostResp    int
	NPostCertIss int
	NGetCert     int
	NPostCertRev int
}

func (s *mockHTTPServer) GetDirectory() (*Directory, HTTPResponse, error) {
	s.NDir++
	return &Directory{}, HTTPResponse{}, nil
}

func (s *mockHTTPServer) PostRegistration(accountKey crypto.PublicKey, uri string, req *Registration) (*Registration, HTTPResponse, error) {
	s.NPostReg++
	return &Registration{}, HTTPResponse{}, nil
}

func (s *mockHTTPServer) PostAccountRecovery(accountKey crypto.PublicKey, uri string, req *Recovery) (*Registration, HTTPResponse, error) {
	s.NPostAccRec++
	return &Registration{}, HTTPResponse{}, nil
}

func (s *mockHTTPServer) PostAuthorization(accountKey crypto.PublicKey, uri string, req *Authorization) (*Authorization, HTTPResponse, error) {
	s.NPostAuthz++
	return &Authorization{}, HTTPResponse{}, nil
}

func (s *mockHTTPServer) GetAuthorization(uri string) (*Authorization, HTTPResponse, error) {
	s.NGetAuthz++
	return &Authorization{}, HTTPResponse{}, nil
}

func (s *mockHTTPServer) PostResponse(accountKey crypto.PublicKey, uri string, req Response) (Challenge, HTTPResponse, error) {
	s.NPostResp++
	return &GenericChallenge{}, HTTPResponse{}, nil
}

func (s *mockHTTPServer) PostCertificateIssuance(accountKey crypto.PublicKey, uri string, req *CertificateIssuance) ([]byte, HTTPResponse, error) {
	s.NPostCertIss++
	return nil, HTTPResponse{}, nil
}

func (s *mockHTTPServer) GetCertificate(uri string) ([]byte, HTTPResponse, error) {
	s.NGetCert++
	return nil, HTTPResponse{}, nil
}

func (s *mockHTTPServer) PostCertificateRevocation(accountKey crypto.PublicKey, uri string, req *Certificate) (HTTPResponse, error) {
	s.NPostCertRev++
	return HTTPResponse{}, nil
}
