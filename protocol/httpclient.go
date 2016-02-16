package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"

	"github.com/square/go-jose"
)

const (
	acceptHeader      = "Accept"
	contentTypeHeader = "Content-Type"
)

var (
	ErrNoNonce  = errors.New("no nonce available")
	ErrNoSigner = errors.New("no signer in client")

	replayNonceRE = regexp.MustCompile("^[A-Za-z0-9_-]+$")
)

// HTTPClient is an ACME HTTP client. It is an adapter between the
// standard HTTP client and ACME clients. It marshals requests,
// identifies errors, unmarshals responses and records nonces.
type HTTPClient struct {
	http   HTTPDoer
	signer jose.Signer
	nonces nonceStack
}

// An HTTPDoer is able to make HTTP requests. *net/http.Client is an
// example.
type HTTPDoer interface {
	// Do performs an HTTP request.
	Do(*http.Request) (*http.Response, error)
}

// NewHTTPClient returns a new ACME HTTP client using the HTTP client.
// If hc is nil, http.DefaultClient is used.
// signer can be nil, but will cause Post invocations to fail.
func NewHTTPClient(hc HTTPDoer, signer jose.Signer) *HTTPClient {
	if hc == nil {
		hc = http.DefaultClient
	}
	ret := &HTTPClient{
		http:   hc,
		signer: signer,
	}
	if signer != nil {
		signer.SetNonceSource(&ret.nonces)
	}

	return ret
}

// Get performs a GET request to the given URL. It sets the Accept
// header and parses the response into respBody, unless it is nil. If
// respBody is nil, the response body must be closed by the caller.
func (c *HTTPClient) Get(url, accept string, respBody interface{}) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add(acceptHeader, accept)
	return c.do(req, respBody)
}

// Head performs a HEAD request to the given URL. The response body is
// already closed on return.
func (c *HTTPClient) Head(url string) (*http.Response, error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.do(req, nil)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Post performs a POST request to the given URL. It sets the acceptHeader
// and Content-Type headers and parses the response into respBody,
// unless it is nil. If respBody is nil, the response body must be
// closed by the caller.  If reqBody is not nil, it is encoded
// (depending on contentType).
func (c *HTTPClient) Post(url, accept string, reqBody, respBody interface{}) (*http.Response, error) {
	var r io.Reader
	if reqBody != nil {
		if c.signer == nil {
			return nil, ErrNoSigner
		}

		signed, err := signJSON(c.signer, reqBody)
		if err != nil {
			return nil, err
		}

		bs, err := json.Marshal(signed)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(bs)
	}
	req, err := http.NewRequest("POST", url, r)
	if err != nil {
		return nil, err
	}
	req.Header.Add(acceptHeader, accept)
	if r != nil {
		req.Header.Set(contentTypeHeader, JSON)
	}
	return c.do(req, respBody)
}

// do performs the request. HTTP 4xx and 5xx errors are converted to
// ServerError. If respBody is nil, the body of the response must be
// closed by the caller. Otherwise, the body will be parsed into
// respBody and closed.
func (c *HTTPClient) do(req *http.Request, respBody interface{}) (*http.Response, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode / 100 {
	case 2, 3:
		break
	case 4, 5:
		return nil, newServerError(req, resp)
	default:
		return nil, fmt.Errorf("unexpected status to %s %q: %s (%d)", req.Method, req.URL, resp.Status, resp.StatusCode)
	}

	if respBody != nil {
		if err := decodeBody(respBody, resp.Header.Get(contentTypeHeader), resp.Body); err != nil {
			return nil, err
		}
	}

	n := resp.Header.Get(ReplayNonce)
	if replayNonceRE.MatchString(n) {
		c.nonces.add(n)
	}

	return resp, nil
}

// nonceStack is a stack of nonces implementing jose.NonceSource.
type nonceStack struct {
	ns []string
}

// add pushes a nonce to the stack.
func (s *nonceStack) add(n string) {
	s.ns = append(s.ns, n)
}

// Nonce pops a nonce from the stack. Can return ErrNoNonce, in which
// case a non-secure request should be performed to populate the pool.
func (s *nonceStack) Nonce() (string, error) {
	if len(s.ns) == 0 {
		return "", ErrNoNonce
	}

	n := len(s.ns)
	ret := s.ns[n-1]
	s.ns = s.ns[:n-1]
	return ret, nil
}

// ServerError is an error reported by an ACME server.
type ServerError struct {
	// Method is the HTTP method used.
	Method string

	// URL is the request URL.
	URL *url.URL

	// Status is the status string returned by the server.
	Status string

	// StatusCode is the status code returned by the server.
	StatusCode int

	// Problem is the problem object, if one was supplied.
	Problem *Problem
}

// newServerError creates a new ServerError based on a request and response.
func newServerError(req *http.Request, resp *http.Response) *ServerError {
	if resp.Header.Get(contentTypeHeader) != ProblemJSON {
		return &ServerError{req.Method, req.URL, resp.Status, resp.StatusCode, nil}
	}

	p := &Problem{}
	if err := decodeBody(p, ProblemJSON, resp.Body); err != nil {
		return &ServerError{req.Method, req.URL, resp.Status, resp.StatusCode, nil}
	}
	return &ServerError{req.Method, req.URL, resp.Status, resp.StatusCode, p}
}

func (e *ServerError) Error() string {
	if e.Problem == nil {
		return fmt.Sprintf("server error on %s %s: %s", e.Method, e.URL, e.Status)
	}

	return fmt.Sprintf("server error on %s %s: %s (%d %s)", e.Method, e.URL, e.Problem.Detail, e.StatusCode, e.Problem.Type)
}

// decodeBody decodes an HTTP body as a specific contentType.
func decodeBody(out interface{}, contentType string, r io.Reader) error {
	switch contentType {
	case JSON, ProblemJSON:
		return json.NewDecoder(r).Decode(out)

	case PKIXCert:
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
	case JSON, ProblemJSON:
		b := bytes.NewBuffer(nil)
		if err := json.NewEncoder(b).Encode(in); err != nil {
			return nil, err
		}
		return b, nil

	case PKIXCert:
		bsin, ok := in.(*[]byte)
		if !ok {
			return nil, fmt.Errorf("expected input to be a *[]byte, got %T", in)
		}
		return bytes.NewReader(*bsin), nil

	default:
		return nil, fmt.Errorf("unhandled content type: %q", contentType)
	}
}
