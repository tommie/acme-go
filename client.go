package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/square/go-jose"
	"github.com/tommie/acme-go/protocol"
)

var (
	ErrUnsupported = errors.New("unsupported operation")
)

// ClientAccount represents a client for connecting to an ACME
// account. Instances are not concurrency-safe.
type ClientAccount struct {
	// URI is the registration URI of the account.
	URI    string
	Key    crypto.PublicKey
	dirURI string
	http   getPoster

	// d is a cache with URIs to well-known endpoints.
	d *protocol.Directory
	// reg is a cache used to get the authz and cert enumeration URIs.
	reg *protocol.Registration
}

type getPoster interface {
	protocol.Getter
	protocol.Poster
}

// NewClientAccount creates a new account client by supplying the
// directory URI, account registration URI and the account key.
func NewClientAccount(dirURI, regURI string, accountKey crypto.PrivateKey) (*ClientAccount, error) {
	type hasPublic interface {
		Public() crypto.PublicKey
	}
	var pub crypto.PublicKey
	if hp, ok := accountKey.(hasPublic); ok {
		pub = hp.Public()
	}

	s, err := jose.NewSigner(signatureAlgo(accountKey), accountKey)
	if err != nil {
		return nil, err
	}

	hc := newHTTPClient(s)
	// Get an initial nonce and validate the URI.
	if _, err := hc.Head(dirURI); err != nil {
		return nil, err
	}

	return &ClientAccount{
		URI:    regURI,
		Key:    pub,
		dirURI: dirURI,
		http:   hc,
	}, nil
}

// UpdateRegistration allows changing one or more aspects of the
// registration. Takes the same options as RegisterAccount.
func (a *ClientAccount) UpdateRegistration(opts ...RegistrationOpt) (*Registration, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("nothing to update")
	}

	ret, _, err := doRegistration(a.http, a.URI, &protocol.Registration{Resource: protocol.ResourceReg}, opts...)
	return ret, err
}

// Registration fetches the current registration resource. If the
// account registration is not complete, this returns ErrPending.
func (a *ClientAccount) Registration() (*Registration, error) {
	ret, _, err := doRegistration(a.http, a.URI, &protocol.Registration{Resource: protocol.ResourceReg})
	return ret, err
}

// AuthorizeIdentity starts an authorization flow for the given
// identifier. The returned *Authorization may be in pending state and
// require further action through solving returned challenges.
func (a *ClientAccount) AuthorizeIdentity(id Identifier) (*Authorization, error) {
	req := &protocol.Authorization{
		Resource:   protocol.ResourceNewAuthz,
		Identifier: *id.Protocol(),
	}

	d, err := a.directory()
	if err != nil {
		return nil, err
	}

	authz, resp, err := protocol.PostAuthorization(a.http, d.NewAuthz, req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("authorize identity: unexpected HTTP status: %s", resp.Status)
	}

	return newAuthorization(authz, resp)
}

// Authorization returns information about an existing
// authorization. It is up to the server to decide what authorizations
// are available to fetch (pending/valid/invalid).
func (a *ClientAccount) Authorization(uri string) (*Authorization, error) {
	authz, resp, err := protocol.GetAuthorization(a.http, uri)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case http.StatusAccepted:
	case http.StatusOK:
		break
	default:
		return nil, fmt.Errorf("get authorization: unexpected HTTP status: %s", resp.Status)
	}

	return newAuthorization(authz, resp)
}

// AuthorizationURIs returns the list of pending and/or valid
// authorizations, depending on the ACME server implementation. A
// returned URI can be used in a call to Authorization to get more
// information.
func (a *ClientAccount) AuthorizationURIs() ([]string, error) {
	reg, err := a.registration()
	if err != nil {
		return nil, err
	}
	if reg.AuthorizationsURI == "" {
		return nil, ErrUnsupported
	}

	uris, resp, err := protocol.GetAuthorizationURIs(a.http, reg.AuthorizationsURI)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get authorization URIs: unexpected HTTP status: %s", resp.Status)
	}

	return uris.Authorizations, nil
}

// ValidateChallenge notifies the ACME server that a challenge is
// ready to be validated. The ACME client should keep the challenge
// solver running until the associated Authorization stops being
// pending.
func (a *ClientAccount) ValidateChallenge(uri string, req protocol.Response) (protocol.Challenge, error) {
	chal, resp, err := protocol.PostResponse(a.http, uri, req)
	if err != nil {
		return nil, err
	}

	// ACME spec., Sec. 6.5 says OK is returned.
	// Boulder returns Accepted.
	switch resp.StatusCode {
	case http.StatusAccepted:
	case http.StatusOK:
		break
	default:
		return nil, fmt.Errorf("validate challenge: unexpected HTTP status: %s", resp.Status)
	}

	return chal, nil
}

// IssueCertificate signs a certificate signing request if
// authorized. This function will block until the requst is completed
// by the ACME server.
func (a *ClientAccount) IssueCertificate(csr []byte) (*Certificate, error) {
	d, err := a.directory()
	if err != nil {
		return nil, err
	}

	cbs, resp, err := protocol.PostCertificateIssuance(a.http, d.NewCert, &protocol.CertificateIssuance{
		Resource: protocol.ResourceNewCert,
		CSR:      protocol.DERData(csr),
	})
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("issue certificate: unexpected HTTP status: %s", resp.Status)
	}

	uri, err := contentLocation(resp)
	// ACME Spec Sec. 6.6 says servers SHOULD provide Content-Location.
	// Boulder does not, so fall back to Location (which is not stable).
	if err == http.ErrNoLocation {
		uri, err = resp.Location()
	}
	if err != nil {
		return nil, err
	}

	if len(cbs) != 0 {
		return &Certificate{
			Bytes:      cbs,
			URI:        uri.String(),
			IssuerURIs: links(resp, "up"),
		}, err
	}

	ra, _ := retryAfter(resp.Header, 1*time.Second)
	time.Sleep(ra)

	return a.Certificate(uri.String())
}

// Certificate returns an existing certificate. This blocks while the
// certificate is pending.
func (a *ClientAccount) Certificate(uri string) (*Certificate, error) {
	for {
		cbs, resp, err := protocol.GetCertificate(a.http, uri)
		if err != nil {
			return nil, err
		}

		switch resp.StatusCode {
		case http.StatusOK:
			return &Certificate{
				Bytes:      cbs,
				URI:        uri,
				IssuerURIs: links(resp, "up"),
			}, nil

		case http.StatusAccepted:
			break

		default:
			return nil, fmt.Errorf("get certificate: unexpected HTTP status: %s", resp.Status)
		}

		d, _ := retryAfter(resp.Header, 1*time.Second)
		time.Sleep(d)
	}
}

// CertificateURIs returns the list of certificates known for this
// account by the ACME server. Returned URIs can be used in calls to
// Certificate to get more information.
func (a *ClientAccount) CertificateURIs() ([]string, error) {
	reg, err := a.registration()
	if err != nil {
		return nil, err
	}
	if reg.CertificatesURI == "" {
		return nil, ErrUnsupported
	}

	uris, resp, err := protocol.GetCertificateURIs(a.http, reg.CertificatesURI)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get certificate URIs: unexpected HTTP status: %s", resp.Status)
	}

	return uris.Certificates, nil
}

// RevokeCertificate requests a revocation. The given cert should be
// exactly the same as returned by IssueCertificate.
func (a *ClientAccount) RevokeCertificate(cert []byte) error {
	d, err := a.directory()
	if err != nil {
		return err
	}

	req := &protocol.Certificate{
		Resource:    protocol.ResourceRevokeCert,
		Certificate: protocol.DERData(cert),
	}
	resp, err := protocol.PostCertificateRevocation(a.http, d.RevokeCert, req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revoke certificate: unexpected HTTP status: %s", resp.Status)
	}

	return nil
}

// directory returns the ACME server directory, and caches it.
func (a *ClientAccount) directory() (*protocol.Directory, error) {
	if a.d == nil {
		d, _, err := protocol.GetDirectory(a.http, a.dirURI)
		if err != nil {
			return nil, err
		}
		a.d = d
	}

	return a.d, nil
}

// registration returns the current ACME account registration, and caches it.
func (a *ClientAccount) registration() (*protocol.Registration, error) {
	if a.reg == nil {
		reg, _, err := protocol.PostRegistration(a.http, a.URI, &protocol.Registration{
			Resource: protocol.ResourceReg,
		})
		if err != nil {
			return nil, err
		}
		a.reg = reg
	}

	return a.reg, nil
}

// contentLocation returns a resolved Content-Location header. Returns
// http.ErrNoLocation if the header is missing. See also http.Response.Location.
func contentLocation(r *http.Response) (*url.URL, error) {
	s := r.Header.Get("Content-Location")
	if s == "" {
		return nil, http.ErrNoLocation
	}
	if r.Request == nil || r.Request.URL == nil {
		return url.Parse(s)
	}
	return r.Request.URL.Parse(s)
}

// retryAfter returns the Retry-After header, or def.
func retryAfter(hdr http.Header, def time.Duration) (time.Duration, error) {
	n, err := strconv.Atoi(hdr.Get(protocol.RetryAfter))
	if err != nil {
		return def, err
	}

	return time.Duration(n) * time.Second, nil
}

var linkRE = regexp.MustCompile(`^<([^>]+)>(?:;[^=]+=(?:[^;"]+|"[^"]*"))*;rel="([^"]+)"(?:;.*)?$`)

// links returns the specified type of Link headers.
func links(r *http.Response, rel string) []string {
	base := &url.URL{}
	if r.Request != nil && r.Request.URL != nil {
		base = r.Request.URL
	}

	var ret []string
	for _, s := range r.Header[protocol.Link] {
		ss := linkRE.FindStringSubmatch(s)
		if ss == nil || ss[2] != rel {
			continue
		}
		u, err := url.Parse(ss[1])
		if err != nil {
			ret = append(ret, ss[1])
			continue
		}
		ret = append(ret, base.ResolveReference(u).String())
	}

	return ret
}

// signatureAlgo returns a suggested JWS algorithm based on the
// private key. Returns a zero value if none exists.
func signatureAlgo(key crypto.PrivateKey) jose.SignatureAlgorithm {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		// This is a generalization of what the ECDH algorithm
		// uses in the ACME spec.
		if k.Curve.Params().BitSize < 256 {
			return jose.ES256
		} else if k.Curve.Params().BitSize < 521 {
			return jose.ES384
		} else {
			return jose.ES512
		}

	case *rsa.PrivateKey:
		// RS256 is the default in the letsencrypt client.
		return jose.RS256
	}

	return ""
}
