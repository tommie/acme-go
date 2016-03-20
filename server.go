package acme

import (
	"crypto"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tommie/acme-go/protocol"
)

// A Server provides high-level entrypoints for ACME requests. Normally
// functions must be concurrency-safe. Returning a protocol.ServerError
// from any function allows control over HTTP error status codes.
type Server interface {
	// RegisterAccount associates the given key with an account and
	// sets registration information. Returns the complete
	// registration resource.
	RegisterAccount(accountKey crypto.PublicKey, reg *Registration) (*Registration, error)

	// Authorization returns the authorization resource associated
	// with the given URI. It was previously started by
	// ServerAccount.AuthorizeIdentity.
	Authorization(uri string) (*Authorization, error)

	// Certificate returns the certificate resource associated
	// with the given URI. It was issued by ServerAccount.IssueCertificate.
	Certificate(uri string) (*Certificate, error)

	// Account creates a server-side representation of an account. This is called often
	// by the HTTP handler and should be lightweight. The key has been authenticated
	// by verifying the signature of the associated request body.
	Account(accountKey crypto.PublicKey) ServerAccount
}

// A ServerAccount provides high-level entrypoints for ACME requests
// on an account. These have an implicit account key.
type ServerAccount interface {
	// AuthorizeIdentity starts an identity authorization for the given identifier.
	AuthorizeIdentity(id Identifier) (*Authorization, error)
	// IssueCertificate issues a certificate based on the certificate signing request.
	IssueCertificate(csr []byte) (*Certificate, error)
	// RevokeCertificate revokes the previously issued DER-encoded X.509 certificate.
	RevokeCertificate(cert []byte) error
	// UpdateRegistration updates the registration resource and returns the resulting complete resource.
	UpdateRegistration(reg *Registration) (*Registration, error)
	// ValidateChallenge informs the ACME server a challenge has been accepted.
	ValidateChallenge(uri string, req protocol.Response) (protocol.Challenge, error)
}

// An httpServer is a protocol.HTTPServer capable of responding to requests over HTTP.
type httpServer struct {
	s Server
	d *protocol.Directory
}

// NewHTTPServer creates an HTTPServer from a high-level Server.
func NewHTTPServer(s Server, d *protocol.Directory) protocol.HTTPServer {
	return &httpServer{s, d}
}

func (h *httpServer) GetDirectory() (*protocol.Directory, protocol.HTTPResponse, error) {
	return h.d, protocol.HTTPResponse{}, nil
}

func (h *httpServer) PostRegistration(accountKey crypto.PublicKey, uri string, req *protocol.Registration) (*protocol.Registration, protocol.HTTPResponse, error) {
	switch req.Resource {
	case protocol.ResourceNewReg:
		reg, err := h.s.RegisterAccount(accountKey, &Registration{Registration: *req})
		if err != nil {
			return nil, protocol.HTTPResponse{}, err
		}

		hdr := http.Header{locationHeader: []string{reg.URI}}
		if reg.TermsOfServiceURI != "" {
			addLink(hdr, "terms-of-service", reg.TermsOfServiceURI)
		}
		addLink(hdr, "next", h.d.NewAuthz)
		return &reg.Registration, protocol.HTTPResponse{StatusCode: http.StatusCreated, Header: hdr}, nil

	case protocol.ResourceReg:
		acc := h.s.Account(accountKey)
		reg, err := acc.UpdateRegistration(&Registration{Registration: *req, URI: uri})
		if err != nil {
			return nil, protocol.HTTPResponse{}, err
		}

		hdr := http.Header{}
		if reg.TermsOfServiceURI != "" {
			addLink(hdr, "terms-of-service", reg.TermsOfServiceURI)
		}
		addLink(hdr, "next", h.d.NewAuthz)
		return &reg.Registration, protocol.HTTPResponse{Header: hdr}, nil

	default:
		return nil, protocol.HTTPResponse{}, errBadResource
	}
}

func (h *httpServer) PostAccountRecovery(accountKey crypto.PublicKey, uri string, req *protocol.Recovery) (*protocol.Registration, protocol.HTTPResponse, error) {
	return nil, protocol.HTTPResponse{}, &protocol.ServerError{
		StatusCode: http.StatusNotImplemented,
		Problem: &protocol.Problem{
			Type:   protocol.Malformed,
			Detail: "account recovery not implemented",
			Status: http.StatusNotImplemented,
		},
	}
}

func (h *httpServer) PostAuthorization(accountKey crypto.PublicKey, uri string, req *protocol.Authorization) (*protocol.Authorization, protocol.HTTPResponse, error) {
	switch req.Resource {
	case protocol.ResourceNewAuthz:
		id, err := newIdentifier(req.Identifier)
		if err != nil {
			return nil, protocol.HTTPResponse{}, &protocol.ServerError{
				StatusCode: http.StatusBadRequest,
				Problem: &protocol.Problem{
					Type:   protocol.Malformed,
					Detail: err.Error(),
					Status: http.StatusBadRequest,
				},
			}
		}
		acc := h.s.Account(accountKey)
		authz, err := acc.AuthorizeIdentity(id)
		if err != nil {
			return nil, protocol.HTTPResponse{}, err
		}

		hdr := http.Header{locationHeader: []string{authz.URI}}
		addLink(hdr, "next", h.d.NewCert)
		return &authz.Authorization, protocol.HTTPResponse{StatusCode: http.StatusCreated, Header: hdr}, nil

	default:
		return nil, protocol.HTTPResponse{}, errBadResource
	}
}

func (h *httpServer) GetAuthorization(uri string) (*protocol.Authorization, protocol.HTTPResponse, error) {
	authz, err := h.s.Authorization(uri)
	if err != nil {
		return nil, protocol.HTTPResponse{}, err
	}

	hdr := http.Header{locationHeader: []string{authz.URI}}
	if authz.RetryAfter != 0 {
		hdr.Set(protocol.RetryAfter, strconv.Itoa(int((authz.RetryAfter+999*time.Millisecond)/time.Second)))
		return &authz.Authorization, protocol.HTTPResponse{StatusCode: http.StatusAccepted, Header: hdr}, nil
	} else {
		addLink(hdr, "next", h.d.NewCert)
		return &authz.Authorization, protocol.HTTPResponse{Header: hdr}, nil
	}
}

func (h *httpServer) PostResponse(accountKey crypto.PublicKey, uri string, req protocol.Response) (protocol.Challenge, protocol.HTTPResponse, error) {
	switch req.GetResource() {
	case protocol.ResourceChallenge:
		acc := h.s.Account(accountKey)
		chal, err := acc.ValidateChallenge(uri, req)
		// TODO: Add up link.
		// ACME spec., Sec. 6.5 says OK is returned.
		// Boulder returns Accepted.
		return chal, protocol.HTTPResponse{}, err

	default:
		return nil, protocol.HTTPResponse{}, errBadResource
	}
}

func (h *httpServer) PostCertificateIssuance(accountKey crypto.PublicKey, uri string, req *protocol.CertificateIssuance) ([]byte, protocol.HTTPResponse, error) {
	switch req.Resource {
	case protocol.ResourceNewCert:
		acc := h.s.Account(accountKey)
		cert, err := acc.IssueCertificate(req.CSR)
		if err != nil {
			return nil, protocol.HTTPResponse{}, err
		}

		hdr := http.Header{locationHeader: []string{cert.URI}}
		for _, u := range cert.IssuerURIs {
			addLink(hdr, "up", u)
		}
		if cert.RetryAfter != 0 {
			hdr.Set(protocol.RetryAfter, strconv.Itoa(int((cert.RetryAfter+999*time.Millisecond)/time.Second)))
			return nil, protocol.HTTPResponse{StatusCode: http.StatusAccepted, Header: hdr}, nil
		} else {
			addLink(hdr, "revoke", h.d.RevokeCert)
			// TODO: Add author link.
			return cert.Bytes, protocol.HTTPResponse{StatusCode: http.StatusCreated, Header: hdr}, nil
		}

	default:
		return nil, protocol.HTTPResponse{}, errBadResource
	}
}

func (h *httpServer) GetCertificate(uri string) ([]byte, protocol.HTTPResponse, error) {
	cert, err := h.s.Certificate(uri)
	if err != nil {
		return nil, protocol.HTTPResponse{}, err
	}

	hdr := http.Header{locationHeader: []string{cert.URI}}
	for _, u := range cert.IssuerURIs {
		addLink(hdr, "up", u)
	}
	addLink(hdr, "revoke", h.d.RevokeCert)
	// TODO: Add author link.
	return cert.Bytes, protocol.HTTPResponse{Header: hdr}, nil
}

func (h *httpServer) PostCertificateRevocation(accountKey crypto.PublicKey, uri string, req *protocol.Certificate) (protocol.HTTPResponse, error) {
	switch req.Resource {
	case protocol.ResourceRevokeCert:
		acc := h.s.Account(accountKey)
		return protocol.HTTPResponse{}, acc.RevokeCertificate(req.Certificate)

	default:
		return protocol.HTTPResponse{}, errBadResource
	}
}

// BoulderDirectory creates a directory for use with protocol.RegisterBoulderHTTP.
// The root URI must be absolute.
func BoulderDirectory(root *url.URL) *protocol.Directory {
	s := strings.TrimRight(root.String(), "/")

	return &protocol.Directory{
		NewReg:     s + protocol.NewRegPath,
		NewAuthz:   s + protocol.NewAuthzPath,
		NewCert:    s + protocol.NewCertPath,
		RevokeCert: s + protocol.RevokeCertPath,
	}
}

// RegisterBoulderHTTP registers the given server under the http.ServeMux h
// with Boulder-compatible paths. The root URI must be absolute and point to
// the root of h.
func RegisterBoulderHTTP(h protocol.HTTPHandlerHandler, root *url.URL, s Server, ns protocol.NonceSource) {
	protocol.RegisterBoulderHTTP(h, NewHTTPServer(s, BoulderDirectory(root)), ns)
}

// addLink adds a Link header.
func addLink(h http.Header, rel, url string) {
	h.Add(protocol.Link, fmt.Sprintf(`<%s>;rel="%s"`, url, rel))
}

const locationHeader = "Location"

var errBadResource = &protocol.ServerError{
	StatusCode: http.StatusBadRequest,
	Problem: &protocol.Problem{
		Type:   protocol.Malformed,
		Detail: "bad resource",
		Status: http.StatusBadRequest,
	},
}
