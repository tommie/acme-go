package protocol

import (
	"fmt"
	"net/http"
)

// GetDirectory looks up a directory in the given location. ACME Section 6.2.
func GetDirectory(g Getter, uri string) (*Directory, *http.Response, error) {
	ret := &Directory{}
	resp, err := g.Get(uri, JSON, ret)
	return ret, resp, err
}

func GetAuthorizationURIs(g Getter, uri string) (*AuthorizationURIs, *http.Response, error) {
	ret := &AuthorizationURIs{}
	resp, err := g.Get(uri, JSON, ret)
	return ret, resp, err
}

func GetCertificateURIs(g Getter, uri string) (*CertificateURIs, *http.Response, error) {
	ret := &CertificateURIs{}
	resp, err := g.Get(uri, JSON, ret)
	return ret, resp, err
}

// PostRegistration sends a new-reg or reg request. ACME Section 6.3.
func PostRegistration(p Poster, uri string, req *Registration) (*Registration, *http.Response, error) {
	if req.Resource != ResourceNewReg && req.Resource != ResourceReg {
		return nil, nil, fmt.Errorf("invalid registration resource: %s", req.Resource)
	}
	if req.Key != nil {
		return nil, nil, fmt.Errorf("Key present in registration request")
	}
	if req.AuthorizationsURI != "" {
		return nil, nil, fmt.Errorf("AuthorizationsURI present in registration request")
	}
	if req.CertificatesURI != "" {
		return nil, nil, fmt.Errorf("CertificatesURI present in registration request")
	}

	ret := &Registration{}
	resp, err := p.Post(uri, JSON, req, ret)
	return ret, resp, err
}

// PostAccountRecovery sends a recover-reg request. ACME Section 6.4.
func PostAccountRecovery(p Poster, uri string, req *Recovery) (*Registration, *http.Response, error) {
	if req.Resource != ResourceRecoverReg {
		return nil, nil, fmt.Errorf("invalid account recovery resource: %s", req.Resource)
	}

	ret := &Registration{}
	resp, err := p.Post(uri, JSON, req, ret)
	return ret, resp, err
}

// PostAuthorization sends a new-authz or authz request. ACME Section 6.5.
func PostAuthorization(p Poster, uri string, req *Authorization) (*Authorization, *http.Response, error) {
	if req.Resource != ResourceNewAuthz && req.Resource != ResourceAuthz {
		return nil, nil, fmt.Errorf("invalid authorization resource: %s", req.Resource)
	}
	if req.Status != "" {
		return nil, nil, fmt.Errorf("Status present in authorization request")
	}
	if req.Expires != nil {
		return nil, nil, fmt.Errorf("Expires present in authorization request")
	}
	if req.Challenges != nil {
		return nil, nil, fmt.Errorf("Challenges present in authorization request")
	}
	if req.Combinations != nil {
		return nil, nil, fmt.Errorf("Combinations present in authorization request")
	}

	ret := &Authorization{}
	resp, err := p.Post(uri, JSON, req, ret)
	return ret, resp, err
}

// GetAuthorization requests information about an authz resource. ACME Section 6.5.
func GetAuthorization(g Getter, uri string) (*Authorization, *http.Response, error) {
	ret := &Authorization{}
	resp, err := g.Get(uri, JSON, ret)
	return ret, resp, err
}

// PostResponse sends a response to a challenge. ACME Section 6.5.
func PostResponse(p Poster, uri string, req Response) (Challenge, *http.Response, error) {
	if req.GetResource() != ResourceChallenge {
		return nil, nil, fmt.Errorf("invalid response resource: %s", req.GetResource())
	}

	var ret anyChallenge
	resp, err := p.Post(uri, JSON, req, &ret)
	return ret.c, resp, err
}

// PostCertificateIssuance sends a new-cert request. ACME Section 6.6.
func PostCertificateIssuance(p Poster, uri string, req *CertificateIssuance) ([]byte, *http.Response, error) {
	if req.Resource != ResourceNewCert {
		return nil, nil, fmt.Errorf("invalid certificate issuance resource: %s", req.Resource)
	}

	var ret []byte
	resp, err := p.Post(uri, PKIXCert, req, &ret)
	return ret, resp, err
}

// GetCertificate requests information about a cert resource. ACME Section 6.6.
func GetCertificate(g Getter, uri string) ([]byte, *http.Response, error) {
	var ret []byte
	resp, err := g.Get(uri, PKIXCert, &ret)
	return ret, resp, err
}

// PostCertificateRevocation sends a revoke-cert request. ACME Section 6.7.
func PostCertificateRevocation(p Poster, uri string, req *Certificate) (*http.Response, error) {
	if req.Resource != ResourceRevokeCert {
		return nil, fmt.Errorf("invalid certificate revocation resource: %s", req.Resource)
	}

	return p.Post(uri, "*/*", req, nil)
}

// Getter is an interface to perform ACME HTTP GET/HEAD requests. It is
// an adapter between the protocol and http.Client.
type Getter interface {
	// Get performs a GET request to the given URL. It sets the Accept
	// header and parses the response into respBody, unless it is nil. If
	// respBody is nil, the response body must be closed by the caller.
	Get(url, accept string, respBody interface{}) (*http.Response, error)
}

// Poster is an interface to perform ACME HTTP POST requests. It is an
// adapter between the protocol and http.Client.
type Poster interface {
	// Post performs a POST request to the given URL. It sets the
	// Accept and Content-Type headers and parses the response
	// into respBody, unless it is nil. The response body reader
	// is already closed on return. If reqBody is not nil, it is
	// encoded (depending on contentType). The reqBody will be
	// wrapped in a jose.JsonWebSignature.
	Post(url, accept string, reqBody, respBody interface{}) (*http.Response, error)
}
