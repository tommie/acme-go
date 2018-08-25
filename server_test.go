package acme

import (
	"bytes"
	"crypto"
	"net/url"
	"testing"
	"time"

	"github.com/tommie/acme-go/protocol"
)

func TestServerPostRegistration(t *testing.T) {
	s := mockServer{}
	hs := NewHTTPServer(&s, &protocol.Directory{})
	s.RespReg = &Registration{
		URI:               "/registered",
		TermsOfServiceURI: "http://example.com/tos",
	}
	got, hresp, err := hs.PostRegistration(testPublicKey, protocol.NewRegPath, &protocol.Registration{Resource: protocol.ResourceNewReg})
	if err != nil {
		t.Fatalf("PostRegistration failed: %v", err)
	}
	if got == nil {
		t.Errorf("PostRegistration: got %v, want %v", got, nil)
	}
	if want := "/registered"; hresp.Header.Get(locationHeader) != want {
		t.Errorf("PostRegistration Location: got %q, want %q", hresp.Header.Get(locationHeader), want)
	}

	s.RespReg = &Registration{
		URI:               "/updated",
		TermsOfServiceURI: "http://example.com/tos",
	}
	got, hresp, err = hs.PostRegistration(testPublicKey, protocol.RegPath, &protocol.Registration{Resource: protocol.ResourceReg})
	if err != nil {
		t.Fatalf("PostRegistration failed: %v", err)
	}
	if got == nil {
		t.Errorf("PostRegistration: got %v, want %v", got, nil)
	}
}

func TestServerPostAuthorization(t *testing.T) {
	s := mockServer{}
	hs := NewHTTPServer(&s, &protocol.Directory{})
	s.RespAuthz = &Authorization{URI: "/authorizing"}
	got, hresp, err := hs.PostAuthorization(testPublicKey, protocol.NewAuthzPath, &protocol.Authorization{
		Resource:   protocol.ResourceNewAuthz,
		Identifier: *DNSIdentifier("").Protocol(),
	})
	if err != nil {
		t.Fatalf("PostAuthorization failed: %v", err)
	}
	if got == nil {
		t.Errorf("PostAuthorization: got %v, want %v", got, nil)
	}
	if want := "/authorizing"; hresp.Header.Get(locationHeader) != want {
		t.Errorf("PostAuthorization Location: got %q, want %q", hresp.Header.Get(locationHeader), want)
	}
}

func TestServerGetAuthorization(t *testing.T) {
	s := mockServer{}
	hs := NewHTTPServer(&s, &protocol.Directory{})
	s.RespAuthz = &Authorization{URI: "/authorized"}
	got, hresp, err := hs.GetAuthorization(protocol.AuthzPath)
	if err != nil {
		t.Fatalf("GetAuthorization failed: %v", err)
	}
	if got == nil {
		t.Errorf("GetAuthorization: got %v, want %v", got, nil)
	}
	if want := "/authorized"; hresp.Header.Get(locationHeader) != want {
		t.Errorf("GetAuthorization Location: got %q, want %q", hresp.Header.Get(locationHeader), want)
	}

	s.RespAuthz = &Authorization{URI: "/authorized", RetryAfter: 1 * time.Minute}
	got, hresp, err = hs.GetAuthorization(protocol.AuthzPath)
	if err != nil {
		t.Fatalf("GetAuthorization failed: %v", err)
	}
	if got == nil {
		t.Errorf("GetAuthorization: got %v, want %v", got, nil)
	}
	if want := "60"; hresp.Header.Get(protocol.RetryAfter) != want {
		t.Errorf("GetAuthorization RetryAfter: got %q, want %q", hresp.Header.Get(locationHeader), want)
	}
}

func TestServerPostResponse(t *testing.T) {
	s := mockServer{}
	hs := NewHTTPServer(&s, &protocol.Directory{})
	got, _, err := hs.PostResponse(testPublicKey, protocol.NewAuthzPath, &protocol.GenericResponse{
		Resource: protocol.ResourceChallenge,
	})
	if err != nil {
		t.Fatalf("PostResponse failed: %v", err)
	}
	if got == nil {
		t.Errorf("PostResponse: got %v, want %v", got, nil)
	}
	if s.NValChal != 1 {
		t.Errorf("PostRegistration NValChal: got %v, want %v", s.NValChal, 1)
	}
}

func TestServerPostCertificateIssuance(t *testing.T) {
	s := mockServer{}
	hs := NewHTTPServer(&s, &protocol.Directory{})
	s.RespCert = &Certificate{
		Bytes:      []byte("hello"),
		IssuerURIs: []string{"http://example.com/issuer"},
	}
	got, _, err := hs.PostCertificateIssuance(testPublicKey, protocol.NewCertPath, &protocol.CertificateIssuance{
		Resource: protocol.ResourceNewCert,
	})
	if err != nil {
		t.Fatalf("PostCertificateIssuance failed: %v", err)
	}
	if want := []byte("hello"); !bytes.Equal(got, want) {
		t.Errorf("PostCertificateIssuance: got %v, want %v", got, want)
	}

	s.RespCert = &Certificate{
		Bytes:      []byte("hello"),
		RetryAfter: 1 * time.Minute,
	}
	got, hresp, err := hs.PostCertificateIssuance(testPublicKey, protocol.NewCertPath, &protocol.CertificateIssuance{
		Resource: protocol.ResourceNewCert,
	})
	if err != nil {
		t.Fatalf("PostCertificateIssuance failed: %v", err)
	}
	if want := "60"; hresp.Header.Get(protocol.RetryAfter) != want {
		t.Errorf("PostCertificateIssuance RetryAfter: got %q, want %q", hresp.Header.Get(locationHeader), want)
	}
}

func TestServerGetCertificate(t *testing.T) {
	s := mockServer{}
	hs := NewHTTPServer(&s, &protocol.Directory{})
	s.RespCert = &Certificate{Bytes: []byte("world")}
	got, _, err := hs.GetCertificate(protocol.CertPath)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if want := []byte("world"); !bytes.Equal(got, want) {
		t.Errorf("GetCertificate: got %v, want %v", got, want)
	}
}

func TestServerPostCertificateRevocation(t *testing.T) {
	s := mockServer{}
	hs := NewHTTPServer(&s, &protocol.Directory{})
	_, err := hs.PostCertificateRevocation(testPublicKey, protocol.CertPath, &protocol.Certificate{
		Resource: protocol.ResourceRevokeCert,
	})
	if err != nil {
		t.Fatalf("PostCertificateRevocation failed: %v", err)
	}
	if s.NRevCert != 1 {
		t.Errorf("PostCertificateRevocation NRevCert: got %v, want %v", s.NRevCert, 1)
	}
}

func TestBoulderDirectory(t *testing.T) {
	tsts := []struct {
		Root url.URL

		ExpNewReg string
	}{
		{
			Root: url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/",
			},
			ExpNewReg: "https://example.com/acme/new-reg",
		},
		{
			Root: url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/subdir",
			},
			ExpNewReg: "https://example.com/subdir/acme/new-reg",
		},
		{
			Root: url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/subdir/",
			},
			ExpNewReg: "https://example.com/subdir/acme/new-reg",
		},
	}

	for _, tst := range tsts {
		d := BoulderDirectory(&tst.Root)
		if d.NewReg != tst.ExpNewReg {
			t.Errorf("BoulderDirectory(%q) NewReg: got %q, want %q", tst.Root.String(), d.NewReg, tst.ExpNewReg)
		}
	}
}

type mockServer struct {
	RespReg   *Registration
	RespAuthz *Authorization
	RespCert  *Certificate

	NRevCert int
	NValChal int
}

func (s *mockServer) RegisterAccount(accountKey crypto.PublicKey, reg *Registration) (*Registration, error) {
	return s.RespReg, nil
}

func (s *mockServer) Authorization(uri string) (*Authorization, error) {
	return s.RespAuthz, nil
}

func (s *mockServer) Certificate(uri string) (*Certificate, error) {
	return s.RespCert, nil
}

func (s *mockServer) Account(accountKey crypto.PublicKey) ServerAccount {
	return s
}

func (s *mockServer) AuthorizeIdentity(id Identifier) (*Authorization, error) {
	return s.RespAuthz, nil
}

func (s *mockServer) IssueCertificate(csr []byte) (*Certificate, error) {
	return s.RespCert, nil
}

func (s *mockServer) RevokeCertificate(cert []byte) error {
	s.NRevCert++
	return nil
}

func (s *mockServer) UpdateRegistration(reg *Registration) (*Registration, error) {
	return s.RespReg, nil
}

func (s *mockServer) ValidateChallenge(uri string, req protocol.Response) (protocol.Challenge, error) {
	s.NValChal++
	return &protocol.GenericChallenge{}, nil
}
