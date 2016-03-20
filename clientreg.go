package acme

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"net/http"

	"github.com/square/go-jose"
	"github.com/tommie/acme-go/protocol"
)

// RegisterAccount performs an account registration and returns a
// client account on success. dirURI is the ACME directory URI.
func RegisterAccount(dirURI string, accountKey crypto.PrivateKey, opts ...RegistrationOpt) (*ClientAccount, *Registration, error) {
	a, err := NewClientAccount(dirURI, "", accountKey)
	if err != nil {
		return nil, nil, err
	}

	d, err := a.directory()
	if err != nil {
		return nil, nil, err
	}

	reg, err := doRegistration(a.http, d.NewReg, &protocol.Registration{Resource: protocol.ResourceNewReg}, opts...)
	if err != nil {
		return nil, nil, err
	}

	a.URI = reg.URI

	return a, reg, nil
}

type RegistrationOpt func(*protocol.Registration)

func WithContactURIs(contacts ...string) RegistrationOpt {
	return func(r *protocol.Registration) {
		r.ContactURIs = contacts
	}
}

func WithAgreementURI(u string) RegistrationOpt {
	return func(r *protocol.Registration) {
		r.AgreementURI = u
	}
}

func WithRecoveryKeyMaterial(key *ecdsa.PrivateKey, len int) RegistrationOpt {
	return func(r *protocol.Registration) {
		r.RecoveryKey = &protocol.RecoveryKey{
			Client: &jose.JsonWebKey{Key: key},
			Length: len,
		}
	}
}

// doRegistration runs a registration. req needs to have at least
// Resource set. Returns ErrPending and the registration URL if the
// registration is not yet complete.
func doRegistration(hc protocol.Poster, uri string, req *protocol.Registration, opts ...RegistrationOpt) (*Registration, error) {
	for _, opt := range opts {
		opt(req)
	}

	var recPriv *ecdsa.PrivateKey
	if req.RecoveryKey != nil {
		// Save the private key and insert just the public key.
		// The key was assigned through WithRecoveryKeyMaterial,
		// so must be an ecdsa.PrivateKey.
		recPriv = req.RecoveryKey.Client.Key.(*ecdsa.PrivateKey)
		req.RecoveryKey.Client.Key = recPriv.Public()
	}

	reg, resp, err := protocol.PostRegistration(hc, uri, req)
	if err != nil {
		return nil, err
	}

	u, _ := resp.Location()

	switch resp.StatusCode {
	case http.StatusAccepted, http.StatusCreated:
		// TODO: Unspecified behavior.
		// ResourceReg returns StatusAccepted in Boulder.
		break

	default:
		return nil, fmt.Errorf("unexpected HTTP status code: %s", resp.Status)
	}

	ret, err := newRegistration(reg, req, recPriv)
	if err != nil {
		return nil, err
	}

	if u == nil {
		ret.URI = uri
	} else {
		ret.URI = u.String()
	}

	us := links(resp, "terms-of-service")
	if len(us) > 0 {
		ret.TermsOfServiceURI = us[0]
	}

	return ret, nil
}
