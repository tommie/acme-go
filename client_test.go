package acme

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tommie/acme-go/protocol"
)

func TestClientAccountUpdateRegistration(t *testing.T) {
	a, hc := newTestClientAccount()
	hc.posters["/reg/1"] = func(accept string, reqBody, respBody interface{}) (*http.Response, error) {
		req := reqBody.(*protocol.Registration)

		if want := protocol.ResourceReg; req.Resource != want {
			t.Errorf("UpdateRegistration(WithContactURIs) Resource: got %v, want %v", req.Resource, want)
		}
		if want := []string{"mailto:acme@example.com"}; !reflect.DeepEqual(req.ContactURIs, want) {
			t.Errorf("UpdateRegistration(WithContactURIs) ContactURIs: got %v, want %v", req.ContactURIs, want)
		}

		resp := respBody.(*protocol.Registration)
		*resp = *req

		return &http.Response{StatusCode: http.StatusAccepted}, nil
	}

	reg, err := a.UpdateRegistration(WithContactURIs("mailto:acme@example.com"))
	if err != nil {
		t.Fatalf("UpdateRegistration(WithContactURIs) failed: %v", err)
	}
	if want := []string{"mailto:acme@example.com"}; !reflect.DeepEqual(reg.ContactURIs, want) {
		t.Errorf("UpdateRegistration(WithContactURIs) ContactURIs: got %v, want %v", reg.ContactURIs, want)
	}
}

func TestClientAccountRegistration(t *testing.T) {
	a, hc := newTestClientAccount()
	hc.posters["/reg/1"] = func(accept string, reqBody, respBody interface{}) (*http.Response, error) {
		req := reqBody.(*protocol.Registration)

		if want := protocol.ResourceReg; req.Resource != want {
			t.Errorf("Registration() Resource: got %v, want %v", req.Resource, want)
		}

		resp := respBody.(*protocol.Registration)
		resp.ContactURIs = []string{"mailto:acme@example.com"}

		return &http.Response{StatusCode: http.StatusAccepted}, nil
	}

	reg, err := a.Registration()
	if err != nil {
		t.Fatalf("Registration() failed: %v", err)
	}
	if want := []string{"mailto:acme@example.com"}; !reflect.DeepEqual(reg.ContactURIs, want) {
		t.Errorf("Registration() ContactURIs: got %v, want %v", reg.ContactURIs, want)
	}
}

func TestClientAccountAuthorizeIdentity(t *testing.T) {
	a, hc := newTestClientAccount()
	hc.posters["/new-authorization"] = func(accept string, reqBody, respBody interface{}) (*http.Response, error) {
		req := reqBody.(*protocol.Authorization)

		if want := protocol.ResourceNewAuthz; req.Resource != want {
			t.Errorf("AuthorizeIdentity() Resource: got %v, want %v", req.Resource, want)
		}

		resp := respBody.(*protocol.Authorization)
		*resp = *req

		return &http.Response{
			StatusCode: http.StatusCreated,
			Header: http.Header{
				"Location":          []string{"http://example.com/auth/1"},
				protocol.RetryAfter: []string{"42"},
			},
		}, nil
	}

	authz, err := a.AuthorizeIdentity(DNSIdentifier("someplace.example.com"))
	if err != nil {
		t.Fatalf("AuthorizeIdentity() failed: %v", err)
	}
	if want := DNSIdentifier("someplace.example.com"); !reflect.DeepEqual(authz.Identifier, want) {
		t.Errorf("AuthorizeIdentity() Identifier: got %v, want %v", authz.Identifier, want)
	}
	if want := "http://example.com/auth/1"; authz.URI != want {
		t.Errorf("AuthorizeIdentity() URI: got %v, want %v", authz.URI, want)
	}
	if want := 42 * time.Second; authz.RetryAfter != want {
		t.Errorf("AuthorizeIdentity() RetryAfter: got %v, want %v", authz.RetryAfter, want)
	}
}

func TestClientAccountAuthorization(t *testing.T) {
	a, hc := newTestClientAccount()
	hc.getters["/authz/2"] = func(accept string, respBody interface{}) (*http.Response, error) {
		resp := respBody.(*protocol.Authorization)
		resp.Status = protocol.StatusValid
		resp.Identifier = protocol.Identifier{Type: protocol.DNS, Value: "someplace.example.com"}

		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				protocol.RetryAfter: []string{"42"},
			},
			Request: &http.Request{
				URL: &url.URL{Path: "/authz/2"},
			},
		}, nil
	}

	authz, err := a.Authorization("/authz/2")
	if err != nil {
		t.Fatalf("Authorization() failed: %v", err)
	}
	if want := protocol.StatusValid; authz.Status != want {
		t.Errorf("Authorization() Status: got %v, want %v", authz.Status, want)
	}
	if want := "/authz/2"; authz.URI != want {
		t.Errorf("Authorization() URI: got %v, want %v", authz.URI, want)
	}
	if want := 42 * time.Second; authz.RetryAfter != want {
		t.Errorf("Authorization() RetryAfter: got %v, want %v", authz.RetryAfter, want)
	}
}

func TestClientAccountAuthorizationURIs(t *testing.T) {
	a, hc := newTestClientAccount()
	want := []string{"http://example.com/authz/1"}
	hc.posters["/reg/1"] = func(accept string, reqBody, respBody interface{}) (*http.Response, error) {
		req := reqBody.(*protocol.Registration)

		if want := protocol.ResourceReg; req.Resource != want {
			t.Errorf("AuthorizationURIs() Resource: got %v, want %v", req.Resource, want)
		}

		resp := respBody.(*protocol.Registration)
		*resp = *req
		resp.AuthorizationsURI = "http://example.com/reg/1/authz"

		return &http.Response{StatusCode: http.StatusOK}, nil
	}
	hc.getters["http://example.com/reg/1/authz"] = func(accept string, respBody interface{}) (*http.Response, error) {
		resp := respBody.(*protocol.AuthorizationURIs)
		resp.Authorizations = want

		return &http.Response{StatusCode: http.StatusOK}, nil
	}

	got, err := a.AuthorizationURIs()
	if err != nil {
		t.Fatalf("AuthorizationURIs() failed: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AuthorizationURIs(): got %v, want %v", got, want)
	}
}

func TestClientAccountValidateChallenge(t *testing.T) {
	a, hc := newTestClientAccount()
	hc.posters["/authz/2/3"] = func(accept string, reqBody, respBody interface{}) (*http.Response, error) {
		chal := protocol.HTTP01Challenge{Status: protocol.StatusValid}

		// respBody is of unexported type protocol.anyChallenge.
		bs, err := json.Marshal(&chal)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		if err := json.Unmarshal(bs, respBody); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
		}, nil
	}

	chal, err := a.ValidateChallenge("/authz/2/3", &protocol.HTTP01Response{
		Resource:         protocol.ResourceChallenge,
		Type:             protocol.ChallengeHTTP01,
		KeyAuthorization: "1234",
	})
	if err != nil {
		t.Fatalf("ValidateChallenge() failed: %v", err)
	}
	if want := protocol.StatusValid; chal.GetStatus() != want {
		t.Errorf("ValidateChallenge() Status: got %v, want %v", chal.GetStatus(), want)
	}
}

func TestClientAccountIssueCertificate(t *testing.T) {
	a, hc := newTestClientAccount()
	want := []byte("hello world")
	hc.posters["/new-certificate"] = func(accept string, reqBody, respBody interface{}) (*http.Response, error) {
		req := reqBody.(*protocol.CertificateIssuance)

		if want := protocol.ResourceNewCert; req.Resource != want {
			t.Errorf("IssueCertificate() Resource: got %v, want %v", req.Resource, want)
		}

		resp := respBody.(*[]byte)
		*resp = want

		return &http.Response{
			StatusCode: http.StatusCreated,
			Header: http.Header{
				"Content-Location": []string{"http://example.com/cert/3"},
				protocol.Link:      []string{`<http://example.com/cert/a>;rel="up"`, `<http://example.com/cert/b>;rel="up"`},
			},
		}, nil
	}

	cert, err := a.IssueCertificate([]byte("my csr"))
	if err != nil {
		t.Fatalf("IssueCertificate() failed: %v", err)
	}
	if !reflect.DeepEqual(cert.Bytes, want) {
		t.Errorf("IssueCertificate() Bytes: got %v, want %v", cert.Bytes, want)
	}
	if want := "http://example.com/cert/3"; cert.URI != want {
		t.Errorf("IssueCertificate() URI: got %v, want %v", cert.URI, want)
	}
	if want := []string{"http://example.com/cert/a", "http://example.com/cert/b"}; !reflect.DeepEqual(cert.IssuerURIs, want) {
		t.Errorf("IssueCertificate() IssuerURIs: got %v, want %v", cert.IssuerURIs, want)
	}
}

func TestClientAccountIssueCertificatePending(t *testing.T) {
	a, hc := newTestClientAccount()
	want := []byte("hello world")
	hc.posters["/new-certificate"] = func(accept string, reqBody, respBody interface{}) (*http.Response, error) {
		req := reqBody.(*protocol.CertificateIssuance)

		if want := protocol.ResourceNewCert; req.Resource != want {
			t.Errorf("IssueCertificate() Resource: got %v, want %v", req.Resource, want)
		}

		return &http.Response{
			StatusCode: http.StatusCreated,
			Header: http.Header{
				"Content-Location":  []string{"http://example.com/cert/3"},
				protocol.RetryAfter: []string{"0"},
			},
		}, nil
	}
	hc.getters["http://example.com/cert/3"] = func(accept string, respBody interface{}) (*http.Response, error) {
		resp := respBody.(*[]byte)
		*resp = want

		return &http.Response{StatusCode: http.StatusOK}, nil
	}

	cert, err := a.IssueCertificate([]byte("my csr"))
	if err != nil {
		t.Fatalf("IssueCertificate() failed: %v", err)
	}
	if !reflect.DeepEqual(cert.Bytes, want) {
		t.Errorf("IssueCertificate() Bytes: got %v, want %v", cert.Bytes, want)
	}
	if want := "http://example.com/cert/3"; cert.URI != want {
		t.Errorf("IssueCertificate() URI: got %v, want %v", cert.URI, want)
	}
}

func TestClientAccountCertificate(t *testing.T) {
	a, hc := newTestClientAccount()
	want := []byte("hello world")
	i := 0
	hc.getters["/cert/3"] = func(accept string, respBody interface{}) (*http.Response, error) {
		i++

		switch i {
		case 1:
			return &http.Response{
				StatusCode: http.StatusAccepted,
				Header: http.Header{
					protocol.RetryAfter: []string{"0"},
				},
			}, nil

		case 2:
			resp := respBody.(*[]byte)
			*resp = want

			return &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					protocol.Link: []string{`<http://example.com/cert/a>;rel="up"`, `<http://example.com/cert/b>;rel="up"`},
				},
			}, nil

		default:
			return nil, fmt.Errorf("GET /cert/3 invalid state: %d", i)
		}
	}

	cert, err := a.Certificate("/cert/3")
	if err != nil {
		t.Fatalf("Certificate() failed: %v", err)
	}
	if want := 2; i != want {
		t.Fatalf("Certificate() i: got %d GET /cert/3, want %d", i, want)
	}
	if !reflect.DeepEqual(cert.Bytes, want) {
		t.Errorf("Certificate() Bytes: got %v, want %v", cert.Bytes, want)
	}
	if want := "/cert/3"; cert.URI != want {
		t.Errorf("Certificate() URI: got %v, want %v", cert.URI, want)
	}
	if want := []string{"http://example.com/cert/a", "http://example.com/cert/b"}; !reflect.DeepEqual(cert.IssuerURIs, want) {
		t.Errorf("Certificate() IssuerURIs: got %v, want %v", cert.IssuerURIs, want)
	}
}

func TestClientAccountCertificateURIs(t *testing.T) {
	a, hc := newTestClientAccount()
	want := []string{"http://example.com/cert/1"}
	hc.posters["/reg/1"] = func(accept string, reqBody, respBody interface{}) (*http.Response, error) {
		req := reqBody.(*protocol.Registration)

		if want := protocol.ResourceReg; req.Resource != want {
			t.Errorf("CertificateURIs() Resource: got %v, want %v", req.Resource, want)
		}

		resp := respBody.(*protocol.Registration)
		*resp = *req
		resp.CertificatesURI = "http://example.com/reg/1/certs"

		return &http.Response{StatusCode: http.StatusOK}, nil
	}
	hc.getters["http://example.com/reg/1/certs"] = func(accept string, respBody interface{}) (*http.Response, error) {
		resp := respBody.(*protocol.CertificateURIs)
		resp.Certificates = want

		return &http.Response{StatusCode: http.StatusOK}, nil
	}

	got, err := a.CertificateURIs()
	if err != nil {
		t.Fatalf("CertificateURIs() failed: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CertificateURIs(): got %v, want %v", got, want)
	}
}

func TestClientAccountRevokeCertificate(t *testing.T) {
	a, hc := newTestClientAccount()
	hc.posters["/revoke-certificate"] = func(accept string, reqBody, respBody interface{}) (*http.Response, error) {
		req := reqBody.(*protocol.Certificate)

		if want := protocol.ResourceRevokeCert; req.Resource != want {
			t.Errorf("RevokeCertificate() Resource: got %v, want %v", req.Resource, want)
		}

		return &http.Response{StatusCode: http.StatusOK}, nil
	}

	if err := a.RevokeCertificate([]byte("my cert")); err != nil {
		t.Fatalf("RevokeCertificate() failed: %v", err)
	}
}

func TestContentLocation(t *testing.T) {
	exampleURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/"}
	tsts := []struct {
		r *http.Response

		want string
		err  error
	}{
		{
			r:    &http.Response{},
			want: "",
			err:  http.ErrNoLocation,
		},
		{
			r: &http.Response{
				Header: http.Header{
					"Content-Location": []string{},
				},
			},
			want: "",
			err:  http.ErrNoLocation,
		},
		{
			r: &http.Response{
				Header: http.Header{
					"Content-Location": []string{"http://example.com/"},
				},
			},
			want: "http://example.com/",
			err:  nil,
		},
		{
			r: &http.Response{
				Header: http.Header{
					"Content-Location": []string{"http://2.example.com/"},
				},
				Request: &http.Request{
					URL: exampleURL,
				},
			},
			want: "http://2.example.com/",
			err:  nil,
		},
		{
			r: &http.Response{
				Header: http.Header{
					"Content-Location": []string{"/hello"},
				},
				Request: &http.Request{
					URL: exampleURL,
				},
			},
			want: "http://example.com/hello",
			err:  nil,
		},
	}

	for _, tst := range tsts {
		got, err := contentLocation(tst.r)
		if err != tst.err {
			t.Errorf("contentLocation(%v) error: got %v, want %v", tst.r, err, tst.err)
		} else if got == nil && tst.want != "" {
			t.Errorf("contentLocation(%v): got %v, want %v", tst.r, got, tst.want)
		} else if got != nil && got.String() != tst.want {
			t.Errorf("contentLocation(%v): got %v, want %v", tst.r, got, tst.want)
		}
	}
}

func TestRetryAfter(t *testing.T) {
	tsts := []struct {
		hdr http.Header
		def time.Duration

		want time.Duration
		err  string
	}{
		{
			hdr:  http.Header{protocol.RetryAfter: []string{"4711"}},
			def:  42 * time.Second,
			want: 4711 * time.Second,
			err:  "",
		},
		{
			hdr:  http.Header{protocol.RetryAfter: []string{}},
			def:  42 * time.Second,
			want: 42 * time.Second,
			err:  "strconv.ParseInt",
		},
		{
			hdr:  http.Header{protocol.RetryAfter: []string{"abc"}},
			def:  42 * time.Second,
			want: 42 * time.Second,
			err:  "strconv.ParseInt",
		},
	}

	for _, tst := range tsts {
		got, err := retryAfter(tst.hdr, tst.def)
		if err != nil && tst.err != "" && !strings.HasPrefix(err.Error(), tst.err) {
			t.Errorf("retryAfter(%v) error: got %v, want %v", tst.hdr, err, tst.err)
		} else if got != tst.want {
			t.Errorf("retryAfter(%v): got %v, want %v", tst.hdr, got, tst.want)
		}
	}
}

func TestLinks(t *testing.T) {
	tsts := []struct {
		resp *http.Response
		rel  string

		want []string
	}{
		{
			resp: &http.Response{Header: http.Header{protocol.Link: []string{}}},
			rel:  "up",
			want: nil,
		},
		{
			resp: &http.Response{Header: http.Header{protocol.Link: []string{`<http://example.com/>;rel="up"`}}},
			rel:  "up",
			want: []string{"http://example.com/"},
		},
		{
			resp: &http.Response{
				Header:  http.Header{protocol.Link: []string{`</no-host>;rel="up"`}},
				Request: &http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}},
			},
			rel:  "up",
			want: []string{"http://example.com/no-host"},
		},
		{
			resp: &http.Response{Header: http.Header{protocol.Link: []string{`<http://example.com/>;rel="up"`, `<http://example.com/2>;rel="up"`}}},
			rel:  "up",
			want: []string{"http://example.com/", "http://example.com/2"},
		},
		{
			resp: &http.Response{Header: http.Header{protocol.Link: []string{`<http://example.com/>;rel="up"`, `<http://example.com/2>;rel="other"`}}},
			rel:  "up",
			want: []string{"http://example.com/"},
		},
		{
			resp: &http.Response{
				Header: http.Header{protocol.Link: []string{
					`<http://example.com/>;rel="text";title="1"`,
					`<http://example.com/2>;title="2";rel="text"`,
				}},
			},
			rel:  "text",
			want: []string{"http://example.com/", "http://example.com/2"},
		},
	}

	for _, tst := range tsts {
		got := links(tst.resp, tst.rel)
		if !reflect.DeepEqual(got, tst.want) {
			t.Errorf("links(%v, %q): got %v, want %v", tst.resp, tst.rel, got, tst.want)
		}
	}
}

func newTestClientAccount() (*ClientAccount, *stubHTTPClient) {
	hc := newStubHTTPClient()
	hc.getters["/"] = func(accept string, respBody interface{}) (*http.Response, error) {
		d := respBody.(*protocol.Directory)
		d.NewReg = "/new-registration"
		d.NewAuthz = "/new-authorization"
		d.NewCert = "/new-certificate"
		d.RevokeCert = "/revoke-certificate"
		return &http.Response{StatusCode: http.StatusOK}, nil
	}

	return &ClientAccount{
		URI:    "/reg/1",
		Key:    testPublicKey,
		dirURI: "/",
		http:   hc,
	}, hc
}

type stubHTTPClient struct {
	getters map[string]func(accept string, respBody interface{}) (*http.Response, error)
	posters map[string]func(accept string, reqBody, respBody interface{}) (*http.Response, error)
}

func newStubHTTPClient() *stubHTTPClient {
	return &stubHTTPClient{
		getters: map[string]func(accept string, respBody interface{}) (*http.Response, error){},
		posters: map[string]func(accept string, reqBody, respBody interface{}) (*http.Response, error){},
	}
}

func (c *stubHTTPClient) Get(url, accept string, respBody interface{}) (*http.Response, error) {
	f := c.getters[url]
	if f == nil {
		return &http.Response{StatusCode: http.StatusNotFound, Status: "404 No Getter: " + url}, nil
	}

	return f(accept, respBody)
}

func (c *stubHTTPClient) Head(url string) (*http.Response, error) {
	return nil, fmt.Errorf("unexpected HEAD request to %q", url)
}

func (c *stubHTTPClient) Post(url, accept string, reqBody, respBody interface{}) (*http.Response, error) {
	f := c.posters[url]
	if f == nil {
		return &http.Response{StatusCode: http.StatusNotFound, Status: "404 No Poster: " + url}, nil
	}

	return f(accept, reqBody, respBody)
}
