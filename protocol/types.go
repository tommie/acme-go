package protocol

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"gopkg.in/square/go-jose.v2"
)

// DERData is raw DER-encoded data.
type DERData []byte

func (d DERData) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.URLEncoding.EncodeToString([]byte(d)))
}

func (d *DERData) UnmarshalJSON(bs []byte) error {
	var s string
	if err := json.Unmarshal(bs, &s); err != nil {
		return err
	}
	dbs, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	*(*[]byte)(d) = dbs
	return nil
}

// Time is a simple timestamp.
type Time time.Time

func (t Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(t).Format(time.RFC3339))
}

func (t *Time) UnmarshalJSON(bs []byte) error {
	var s string
	if err := json.Unmarshal(bs, &s); err != nil {
		return err
	}

	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}

	*(*time.Time)(t) = ts

	return nil
}

type JSONWebSignature jose.JSONWebSignature

func (s JSONWebSignature) Verify(verificationKey interface{}) ([]byte, error) {
	return jose.JSONWebSignature(s).Verify(verificationKey)
}

func (s JSONWebSignature) MarshalJSON() ([]byte, error) {
	return []byte(jose.JSONWebSignature(s).FullSerialize()), nil
}

func (s *JSONWebSignature) UnmarshalJSON(bs []byte) error {
	ss, err := jose.ParseSigned(string(bs))
	if err != nil {
		return err
	}

	*(*jose.JSONWebSignature)(s) = *ss

	return nil
}

// signJSON encodes the payload as JSON and signs it.
func signJSON(s jose.Signer, payload interface{}) (*JSONWebSignature, error) {
	bs, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	ret, err := s.Sign(bs)
	if err != nil {
		return nil, err
	}

	return (*JSONWebSignature)(ret), nil
}

// An HTTPResponse describes HTTP-specific response fields reported by a server.
type HTTPResponse struct {
	// StatusCode is the HTTP status code.
	StatusCode int

	// Header is a set of headers to return.
	Header http.Header
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

// serverErrorf constructs a ServerError based on an HTTP status code,
// a problem type and a free-text format string.
func serverErrorf(code int, typ ProblemType, fmts string, args ...interface{}) error {
	return &ServerError{
		StatusCode: code,
		Problem: &Problem{
			Type:   typ,
			Detail: fmt.Sprintf(fmts, args...),
			Status: code,
		},
	}
}

func (e *ServerError) Error() string {
	if e.Problem == nil {
		return fmt.Sprintf("server error on %s %s: %s", e.Method, e.URL, e.Status)
	}

	return fmt.Sprintf("server error on %s %s: %s (%d %s)", e.Method, e.URL, e.Problem.Detail, e.StatusCode, e.Problem.Type)
}
