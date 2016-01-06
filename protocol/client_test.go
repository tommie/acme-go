package protocol

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

func TestGetDirectory(t *testing.T) {
	want := &Directory{NewReg: "http://example.com/new-registration"}
	hc := newStubHTTPClient(want, nil)

	got, _, err := GetDirectory(hc, "http://example.com/")
	if err != nil {
		t.Fatalf("GetDirectory failed: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetDirectory: got %+v, want %+v", got, want)
	}

	if want := (query{Method: "GET", URL: "http://example.com/", Accept: JSON}); !reflect.DeepEqual(hc.req, want) {
		t.Errorf("GetDirectory request: got %+v, want %+v", hc.req, want)
	}
}

func TestGetAuthorizationURIs(t *testing.T) {
	want := &AuthorizationURIs{Authorizations: []string{"http://example.com/auth/1"}}
	hc := newStubHTTPClient(want, nil)

	got, _, err := GetAuthorizationURIs(hc, "http://example.com/auth")
	if err != nil {
		t.Fatalf("GetAuthorizationURIs failed: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetAuthorizationURIs: got %+v, want %+v", got, want)
	}

	if want := (query{Method: "GET", URL: "http://example.com/auth", Accept: JSON}); !reflect.DeepEqual(hc.req, want) {
		t.Errorf("GetAuthorizationURIs request: got %+v, want %+v", hc.req, want)
	}
}

func TestGetCertificateURIs(t *testing.T) {
	want := &CertificateURIs{Certificates: []string{"http://example.com/auth/1"}}
	hc := newStubHTTPClient(want, nil)

	got, _, err := GetCertificateURIs(hc, "http://example.com/auth")
	if err != nil {
		t.Fatalf("GetCertificateURIs failed: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetCertificateURIs: got %+v, want %+v", got, want)
	}

	if want := (query{Method: "GET", URL: "http://example.com/auth", Accept: JSON}); !reflect.DeepEqual(hc.req, want) {
		t.Errorf("GetCertificateURIs request: got %+v, want %+v", hc.req, want)
	}
}

func TestPostRegistration(t *testing.T) {
	want := &Registration{Key: testJWK, AuthorizationsURI: "http://example.com/auth"}
	hc := newStubHTTPClient(want, nil)

	req := &Registration{Resource: ResourceNewReg}
	got, _, err := PostRegistration(hc, "http://example.com/new-reg", req)
	if err != nil {
		t.Fatalf("PostRegistration failed: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("PostRegistration: got %+v, want %+v", got, want)
	}

	if want := (query{Method: "POST", URL: "http://example.com/new-reg", Accept: JSON, Body: req}); !reflect.DeepEqual(hc.req, want) {
		t.Errorf("PostRegistration request: got %+v, want %+v", hc.req, want)
	}
}

func TestPostAccountRecovery(t *testing.T) {
	want := &Registration{ContactURIs: []string{"hello world"}}
	hc := newStubHTTPClient(want, nil)

	req := &Recovery{Resource: ResourceRecoverReg, Method: MAC}
	got, _, err := PostAccountRecovery(hc, "http://example.com/recover-reg", req)
	if err != nil {
		t.Fatalf("PostAccountRecovery failed: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("PostAccountRecovery: got %+v, want %+v", got, want)
	}

	if want := (query{Method: "POST", URL: "http://example.com/recover-reg", Accept: JSON, Body: req}); !reflect.DeepEqual(hc.req, want) {
		t.Errorf("PostAccountRecovery request: got %+v, want %+v", hc.req, want)
	}
}

func TestPostAuthorization(t *testing.T) {
	want := &Authorization{Status: StatusValid}
	hc := newStubHTTPClient(want, nil)

	req := &Authorization{Resource: ResourceNewAuthz}
	got, _, err := PostAuthorization(hc, "http://example.com/new-authorization", req)
	if err != nil {
		t.Fatalf("PostAuthorization failed: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("PostAuthorization: got %+v, want %+v", got, want)
	}

	if want := (query{Method: "POST", URL: "http://example.com/new-authorization", Accept: JSON, Body: req}); !reflect.DeepEqual(hc.req, want) {
		t.Errorf("PostAuthorization request: got %+v, want %+v", hc.req, want)
	}
}

func TestGetAuthorization(t *testing.T) {
	want := &Authorization{Status: StatusValid}
	hc := newStubHTTPClient(want, nil)

	got, _, err := GetAuthorization(hc, "http://example.com/auth/0")
	if err != nil {
		t.Fatalf("GetAuthorization failed: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetAuthorization: got %+v, want %+v", got, want)
	}

	if want := (query{Method: "GET", URL: "http://example.com/auth/0", Accept: JSON}); !reflect.DeepEqual(hc.req, want) {
		t.Errorf("GetAuthorization request: got %+v, want %+v", hc.req, want)
	}
}

func TestPostResponse(t *testing.T) {
	want := &HTTP01Challenge{Type: ChallengeHTTP01, Status: StatusValid}
	hc := newStubHTTPClient(want, nil)

	req := &HTTP01Response{Resource: ResourceChallenge, Type: ChallengeHTTP01}
	got, _, err := PostResponse(hc, "http://example.com/chal/0", req)
	if err != nil {
		t.Fatalf("PostResponse failed: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("PostResponse: got %+v, want %+v", got, want)
	}

	if want := (query{Method: "POST", URL: "http://example.com/chal/0", Accept: JSON, Body: req}); !reflect.DeepEqual(hc.req, want) {
		t.Errorf("PostResponse request: got %+v, want %+v", hc.req, want)
	}
}

func TestPostCertificateIssuance(t *testing.T) {
	want := []byte("cert data")
	hc := newStubHTTPClient(want, nil)

	req := &CertificateIssuance{Resource: ResourceNewCert}
	got, _, err := PostCertificateIssuance(hc, "http://example.com/new-cert", req)
	if err != nil {
		t.Fatalf("PostCertificateIssuance failed: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("PostCertificateIssuance: got %+v, want %+v", got, want)
	}

	if want := (query{Method: "POST", URL: "http://example.com/new-cert", Accept: PKIXCert, Body: req}); !reflect.DeepEqual(hc.req, want) {
		t.Errorf("PostCertificateIssuance request: got %+v, want %+v", hc.req, want)
	}
}

func TestGetCertificate(t *testing.T) {
	want := []byte("cert data")
	hc := newStubHTTPClient(want, nil)

	got, _, err := GetCertificate(hc, "http://example.com/cert/0")
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetCertificate: got %+v, want %+v", got, want)
	}

	if want := (query{Method: "GET", URL: "http://example.com/cert/0", Accept: PKIXCert}); !reflect.DeepEqual(hc.req, want) {
		t.Errorf("GetCertificate request: got %+v, want %+v", hc.req, want)
	}
}

func TestPostCertificateRevocation(t *testing.T) {
	hc := newStubHTTPClient(nil, nil)

	req := &Certificate{Resource: ResourceRevokeCert}
	_, err := PostCertificateRevocation(hc, "http://example.com/revoke-cert", req)
	if err != nil {
		t.Fatalf("PostCertificateRevocation failed: %v", err)
	}

	if want := (query{Method: "POST", URL: "http://example.com/revoke-cert", Accept: "*/*", Body: req}); !reflect.DeepEqual(hc.req, want) {
		t.Errorf("PostCertificateRevocation request: got %+v, want %+v", hc.req, want)
	}
}

// stubHTTPClient is a protocol.HTTPClient responding with a canned response.
type stubHTTPClient struct {
	respBody interface{}
	err      error

	req query
}

type query struct {
	Method string
	URL    string
	Accept string
	Body   interface{}
}

func newStubHTTPClient(respBody interface{}, err error) *stubHTTPClient {
	return &stubHTTPClient{
		respBody: respBody,
		err:      err,
	}
}

func (c *stubHTTPClient) Get(url, accept string, respBody interface{}) (*http.Response, error) {
	c.req = query{Method: "GET", URL: url, Accept: accept}

	return c.respond(respBody)
}

func (c *stubHTTPClient) Head(url string) (*http.Response, error) {
	c.req = query{Method: "HEAD", URL: url}

	return nil, c.err
}

func (c *stubHTTPClient) Post(url, accept string, reqBody, respBody interface{}) (*http.Response, error) {
	c.req = query{Method: "POST", URL: url, Accept: accept, Body: reqBody}

	return c.respond(respBody)
}

func (c *stubHTTPClient) respond(respBody interface{}) (*http.Response, error) {
	if c.respBody != nil {
		bs, err := json.Marshal(c.respBody)
		if err != nil {
			panic(err)
		}

		if err := json.Unmarshal(bs, respBody); err != nil {
			panic(err)
		}
	}

	return &http.Response{}, c.err
}
