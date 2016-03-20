package protocol

import (
	"crypto"
	"net/http"
)

// An HTTPServer responds to incoming ACME requests. The request data
// has already been authenticated where possible.
type HTTPServer interface {
	// GetDirectory sends a directory response. ACME Section 6.2.
	GetDirectory() (*Directory, HTTPResponse, error)
	// PostRegistration sends a new-reg or reg response. ACME Section 6.3.
	PostRegistration(accountKey crypto.PublicKey, uri string, req *Registration) (*Registration, HTTPResponse, error)
	// PostAccountRecovery sends a recover-reg response. ACME Section 6.4.
	PostAccountRecovery(accountKey crypto.PublicKey, uri string, req *Recovery) (*Registration, HTTPResponse, error)
	// PostAuthorization sends a new-authz or authz response. ACME Section 6.5.
	PostAuthorization(accountKey crypto.PublicKey, uri string, req *Authorization) (*Authorization, HTTPResponse, error)
	// GetAuthorization returns information about an authz resource. ACME Section 6.5.
	GetAuthorization(uri string) (*Authorization, HTTPResponse, error)
	// PostResponse sends a response to a challenge. ACME Section 6.5.
	PostResponse(accountKey crypto.PublicKey, uri string, req Response) (Challenge, HTTPResponse, error)
	// PostCertificateIssuance sends a new-cert request. ACME Section 6.6.
	PostCertificateIssuance(accountKey crypto.PublicKey, uri string, req *CertificateIssuance) ([]byte, HTTPResponse, error)
	// GetCertificate returns information about a cert resource. ACME Section 6.6.
	GetCertificate(uri string) ([]byte, HTTPResponse, error)
	// PostCertificateRevocation sends a revoke-cert response. ACME Section 6.7.
	PostCertificateRevocation(accountKey crypto.PublicKey, uri string, req *Certificate) (HTTPResponse, error)
}

// An HTTPDispatcher provides the lowest level interpretation of the
// ACME protocol, mapping URIs to resources and validates request
// data.
type HTTPDispatcher struct {
	s  HTTPServer
	ns NonceSource
}

// NewHTTPDispatcher creates a new dispatcher for the given server
// with the given nonce source used to create response nonces and
// validate request nonces. Both s and ns must be concurrency-safe.
func NewHTTPDispatcher(s HTTPServer, ns NonceSource) *HTTPDispatcher {
	return &HTTPDispatcher{s, ns}
}

// ServeDirectory serves up the ACME directory.
func (d *HTTPDispatcher) ServeDirectory(w http.ResponseWriter, r *http.Request) {
	d.serve(w, r, JSON,
		func() (interface{}, HTTPResponse, error) {
			return d.s.GetDirectory()
		}, nil, nil)
}

// ServeAuthz serves GetAuthorization and PostAuthorization for an
// authorization resource.
func (d *HTTPDispatcher) ServeAuthz(w http.ResponseWriter, r *http.Request) {
	var authz Authorization
	d.serve(w, r, JSON,
		func() (interface{}, HTTPResponse, error) {
			return d.s.GetAuthorization(r.URL.String())
		},
		&authz,
		func(key crypto.PublicKey) (interface{}, HTTPResponse, error) {
			return d.s.PostAuthorization(key, r.URL.String(), &authz)
		})
}

// ServeNewAuthz serves PostAuthorization for new registrations, by
// the NewReg directory entry.
func (d *HTTPDispatcher) ServeNewAuthz(w http.ResponseWriter, r *http.Request) {
	var authz Authorization
	d.serve(w, r, JSON, nil,
		&authz,
		func(key crypto.PublicKey) (interface{}, HTTPResponse, error) {
			return d.s.PostAuthorization(key, r.URL.String(), &authz)
		})
}

// ServeCert serves GetCertificate for a certificate resource.
func (d *HTTPDispatcher) ServeCert(w http.ResponseWriter, r *http.Request) {
	d.serve(w, r, JSON,
		func() (interface{}, HTTPResponse, error) {
			return d.s.GetCertificate(r.URL.String())
		}, nil, nil)
}

// ServeNewCert serves PostCertificateIssuance for the NewCert directory entry.
func (d *HTTPDispatcher) ServeNewCert(w http.ResponseWriter, r *http.Request) {
	var cert CertificateIssuance
	d.serve(w, r, PKIXCert, nil,
		&cert,
		func(key crypto.PublicKey) (interface{}, HTTPResponse, error) {
			return d.s.PostCertificateIssuance(key, r.URL.String(), &cert)
		})
}

// ServeChallenge serves PostResponse for a challenge resource.
func (d *HTTPDispatcher) ServeChallenge(w http.ResponseWriter, r *http.Request) {
	var resp anyResponse
	d.serve(w, r, JSON, nil,
		&resp,
		func(key crypto.PublicKey) (interface{}, HTTPResponse, error) {
			return d.s.PostResponse(key, r.URL.String(), resp.r)
		})
}

// ServeRecoverReg serves PostAccountRecovery for a registration resource.
func (d *HTTPDispatcher) ServeRecoverReg(w http.ResponseWriter, r *http.Request) {
	var rec Recovery
	d.serve(w, r, JSON, nil,
		&rec,
		func(key crypto.PublicKey) (interface{}, HTTPResponse, error) {
			return d.s.PostAccountRecovery(key, r.URL.String(), &rec)
		})
}

// ServeReg serves PostRegistration for a registration resource.
func (d *HTTPDispatcher) ServeReg(w http.ResponseWriter, r *http.Request) {
	var reg Registration
	d.serve(w, r, JSON, nil,
		&reg,
		func(key crypto.PublicKey) (interface{}, HTTPResponse, error) {
			return d.s.PostRegistration(key, r.URL.String(), &reg)
		})
}

// ServeRevokeCert serves PostCertificateRevocation for the RevokeCert
// directory entry.
func (d *HTTPDispatcher) ServeRevokeCert(w http.ResponseWriter, r *http.Request) {
	var cert Certificate
	d.serve(w, r, "*/*", nil,
		&cert,
		func(key crypto.PublicKey) (interface{}, HTTPResponse, error) {
			hresp, err := d.s.PostCertificateRevocation(key, r.URL.String(), &cert)
			return nil, hresp, err
		})
}

// serve handles all methods of one path. It validates the request
// Accept header against the accept argument and unmarshals the
// request body into body. If either get or post is nil, a request
// with that method will return MethodNotAllowed. HEAD requests are
// always valid.
func (d *HTTPDispatcher) serve(w http.ResponseWriter, r *http.Request, accept string,
	get func() (interface{}, HTTPResponse, error),
	body interface{},
	post func(crypto.PublicKey) (interface{}, HTTPResponse, error)) {

	switch r.Method {
	case "HEAD":
		writeResponse(w, r, nil, &HTTPResponse{}, d.ns)

	case "GET":
		if get == nil {
			writeError(w, serverErrorf(http.StatusMethodNotAllowed, Malformed, "Method %s", r.Method))
			return
		}
		if got := r.Header.Get(acceptHeader); accept != "*/*" && got != accept {
			writeError(w, serverErrorf(http.StatusNotAcceptable, Malformed, "only %s supported, got %s", accept, got))
			return
		}
		resp, hresp, err := get()
		if err != nil {
			writeError(w, err)
			return
		}
		writeResponse(w, r, resp, &hresp, d.ns)

	case "POST":
		if post == nil {
			writeError(w, serverErrorf(http.StatusMethodNotAllowed, Malformed, "Method %s", r.Method))
			return
		}
		if got := r.Header.Get(acceptHeader); accept != "*/*" && got != accept {
			writeError(w, serverErrorf(http.StatusNotAcceptable, Malformed, "only %s supported, got %s", accept, got))
			return
		}
		key, err := readRequest(body, r, d.ns)
		if err != nil {
			writeError(w, err)
			return
		}
		resp, hresp, err := post(key)
		if err != nil {
			writeError(w, err)
			return
		}
		writeResponse(w, r, resp, &hresp, d.ns)

	default:
		writeError(w, serverErrorf(http.StatusMethodNotAllowed, Malformed, "Method %s", r.Method))
	}
}

// BoulderHTTPServeMux registers the dispatcher's endpoint in the
// given http.ServeMux-like object at the same paths as Let's
// Encrypt's Boulder server. These paths are not mandated by the ACME
// specification, but are good defaults.
func RegisterBoulderHTTP(mux HTTPHandlerHandler, s HTTPServer, ns NonceSource) {
	d := NewHTTPDispatcher(s, ns)

	mux.Handle(DirectoryPath, http.HandlerFunc(d.ServeDirectory))
	mux.Handle(NewAuthzPath, http.HandlerFunc(d.ServeNewAuthz))
	mux.Handle(NewCertPath, http.HandlerFunc(d.ServeNewCert))
	mux.Handle(NewRegPath, http.HandlerFunc(d.ServeReg))
	mux.Handle(RevokeCertPath, http.HandlerFunc(d.ServeRevokeCert))

	mux.Handle(AuthzPath, http.HandlerFunc(d.ServeAuthz))
	mux.Handle(CertPath, http.HandlerFunc(d.ServeCert))
	mux.Handle(ChallengePath, http.HandlerFunc(d.ServeChallenge))
	mux.Handle(RecoverRegPath, http.HandlerFunc(d.ServeRecoverReg))
	mux.Handle(RegPath, http.HandlerFunc(d.ServeReg))
}

// HTTPHandlerHandler is an http.ServeMux-like object that can
// register handlers.
type HTTPHandlerHandler interface {
	// Handle registers the given handler to respond to requests for
	// the given path prefix.
	Handle(string, http.Handler)
}
