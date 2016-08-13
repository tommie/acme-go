package acme

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/tommie/acme-go/protocol"
)

func TestCertificateIssuerAuthorizeAndIssue(t *testing.T) {
	var ids []string
	ia := &stubIssuingAccount{
		authzID: func(id Identifier) (*Authorization, error) {
			ids = append(ids, id.String())
			return &Authorization{Authorization: protocol.Authorization{}, Status: protocol.StatusValid}, nil
		},
		issue: func(csr []byte) (*Certificate, error) {
			if !reflect.DeepEqual(csr, testCSR) {
				t.Errorf("AuthorizeAndIssue csr: got %v, want %v", csr, testCSR)
			}
			return &Certificate{URI: "http://example.com/cert/4"}, nil
		},
	}

	got, err := NewCertificateIssuer(ia).AuthorizeAndIssue(testCSR, &stubSolver{})
	if err != nil {
		t.Fatalf("AuthorizeAndIssue failed: %v", err)
	}
	if want := (&Certificate{URI: "http://example.com/cert/4"}); !reflect.DeepEqual(got, want) {
		t.Errorf("AuthorizeAndIssue: got %v, want %v", got, want)
	}
	sort.Strings(ids)
	if want := []string{"dns:a.example.com", "dns:b.example.com"}; !reflect.DeepEqual(ids, want) {
		t.Errorf("AuthorizeAndIssue ids: got %v, want %v", ids, want)
	}
}

func TestCertificateIssuerCancel(t *testing.T) {
	var ci *CertificateIssuer
	ia := &stubIssuingAccount{
		authzID: func(id Identifier) (*Authorization, error) {
			ci.Cancel()
			return &Authorization{Authorization: protocol.Authorization{}, Status: protocol.StatusValid}, nil
		},
	}

	ci = NewCertificateIssuer(ia)
	_, err := ci.AuthorizeAndIssue(testCSR, &stubSolver{})
	if err != ErrCanceled {
		t.Fatalf("AuthorizeAndIssue error: got %v, want %v", err, ErrCanceled)
	}
}

func TestCertificateIssuerAuthorizeIdentitiesPending(t *testing.T) {
	ia := &stubIssuingAccount{
		authzID: func(id Identifier) (*Authorization, error) {
			return &Authorization{
				Authorization: protocol.Authorization{
					Identifier: *id.Protocol(),
					Status:     protocol.StatusPending,
				},
				Status:     protocol.StatusPending,
				Identifier: id,
			}, nil
		},
	}

	got, err := NewCertificateIssuer(ia).authorizeIdentities(testCSR)
	if err != nil {
		t.Fatalf("authorizeIdentities failed: %v", err)
	}
	sort.Sort(byIdentifier(got))
	want := []*Authorization{
		&Authorization{
			Authorization: protocol.Authorization{
				Identifier: protocol.Identifier{Type: protocol.DNS, Value: "a.example.com"},
				Status:     protocol.StatusPending,
			},
			Status:     protocol.StatusPending,
			Identifier: DNSIdentifier("a.example.com"),
		},
		&Authorization{
			Authorization: protocol.Authorization{
				Identifier: protocol.Identifier{Type: protocol.DNS, Value: "b.example.com"},
				Status:     protocol.StatusPending,
			},
			Status:     protocol.StatusPending,
			Identifier: DNSIdentifier("b.example.com"),
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("authorizeIdentities: got %v, want %v", got, want)
	}
}

func TestCertificateIssuerAuthorizeIdentitiesValid(t *testing.T) {
	ia := &stubIssuingAccount{
		authzID: func(id Identifier) (*Authorization, error) {
			return &Authorization{Status: protocol.StatusValid}, nil
		},
	}

	got, err := NewCertificateIssuer(ia).authorizeIdentities(testCSR)
	if err != nil {
		t.Fatalf("authorizeIdentities failed: %v", err)
	}
	want := []*Authorization(nil)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("authorizeIdentities: got %v, want %v", got, want)
	}
}

func TestCertificateIssuerAuthorizeIdentitiesInvalid(t *testing.T) {
	ia := &stubIssuingAccount{
		authzID: func(id Identifier) (*Authorization, error) {
			return &Authorization{
				Status: protocol.StatusInvalid,
			}, nil
		},
	}

	_, err := NewCertificateIssuer(ia).authorizeIdentities(testCSR)
	if !strings.HasPrefix(err.Error(), "authorization invalid") {
		t.Fatalf("authorizeIdentities failed: %v", err)
	}
}

func TestBestCombination(t *testing.T) {
	s := &stubSolver{
		costs: map[protocol.ChallengeType]float64{protocol.ChallengeDNS01: 2, protocol.ChallengeHTTP01: 1},
	}
	dns01Challenge := &protocol.DNS01Challenge{
		Type: protocol.ChallengeDNS01,
	}
	http01Challenge := &protocol.HTTP01Challenge{
		Type: protocol.ChallengeHTTP01,
	}
	tsts := []struct {
		name  string
		authz Authorization

		want []protocol.Challenge
		err  error
	}{
		{
			name: "empty",

			err: ErrUnsolvable,
		},
		{
			name: "one",
			authz: Authorization{
				Authorization: protocol.Authorization{
					Challenges: protocol.Challenges{
						dns01Challenge,
					},
					Combinations: [][]int{[]int{0}},
				},
			},

			want: []protocol.Challenge{dns01Challenge},
		},
		{
			name: "two-1-0",
			authz: Authorization{
				Authorization: protocol.Authorization{
					Challenges: protocol.Challenges{
						dns01Challenge,
						http01Challenge,
					},
					Combinations: [][]int{[]int{1}, []int{0}},
				},
			},

			want: []protocol.Challenge{http01Challenge},
		},
		{
			name: "two-0-1",
			authz: Authorization{
				Authorization: protocol.Authorization{
					Challenges: protocol.Challenges{
						dns01Challenge,
						http01Challenge,
					},
					Combinations: [][]int{[]int{0}, []int{1}},
				},
			},

			want: []protocol.Challenge{http01Challenge},
		},
	}

	for _, tst := range tsts {
		got, err := bestCombination(s, &tst.authz)
		if !matchError(err, tst.err) {
			t.Errorf("[%s] bestCombination ok: got %v, want prefix %v", tst.name, err, tst.err)
		}
		if !reflect.DeepEqual(got, tst.want) {
			t.Errorf("[%s] bestCombination: got %v, want %v", tst.name, got, tst.want)
		}
	}
}

func TestCertificateIssuerStartSolver(t *testing.T) {
	dns01Resp := &protocol.HTTP01Response{Type: protocol.ChallengeHTTP01}
	s := &stubSolver{
		resps: map[protocol.ChallengeType]protocol.Response{protocol.ChallengeDNS01: dns01Resp},
	}
	dns01Challenge := &protocol.DNS01Challenge{
		Type: protocol.ChallengeDNS01,
		URI:  "/chal/5",
	}
	tsts := []struct {
		name   string
		cs     []protocol.Challenge
		status protocol.Status

		wantURIs []string
		err      error
	}{
		{
			name: "empty",
		},
		{
			name: "one challenge",
			cs:   []protocol.Challenge{dns01Challenge},

			wantURIs: []string{"/chal/5"},
		},
		{
			name: "two challenges",
			cs:   []protocol.Challenge{dns01Challenge, dns01Challenge},

			wantURIs: []string{"/chal/5", "/chal/5"},
		},
		{
			name:   "invalid",
			cs:     []protocol.Challenge{dns01Challenge},
			status: protocol.StatusInvalid,

			wantURIs: []string{"/chal/5"},
			err:      fmt.Errorf("challenge validation failed"),
		},
	}

	for _, tst := range tsts {
		var uris []string
		ia := &stubIssuingAccount{
			validate: func(uri string, resp protocol.Response) (protocol.Challenge, error) {
				uris = append(uris, uri)
				return &protocol.GenericChallenge{Type: resp.GetType(), Status: tst.status}, nil
			},
		}
		_, err := NewCertificateIssuer(ia).startSolver(s, tst.cs)
		if !matchError(err, tst.err) {
			t.Errorf("[%s] startSolvers failed: got %v, want prefix %v", tst.name, err, tst.err)
		}
		if !reflect.DeepEqual(uris, tst.wantURIs) {
			t.Errorf("[%s] startSolvers uris: got %v, want %v", tst.name, uris, tst.wantURIs)
		}
	}
}

func TestCertificateIssuerWaitAuthorizations(t *testing.T) {
	tsts := []struct {
		name string
		as   []*Authorization
		sm   map[string][]protocol.Status

		wantURIs []string
		err      error
	}{
		{
			name: "empty",
		},
		{
			name: "valid",
			as: []*Authorization{
				{URI: "/authz/2"},
			},
			sm: map[string][]protocol.Status{
				"/authz/2": []protocol.Status{protocol.StatusValid},
			},

			wantURIs: []string{"/authz/2"},
		},
		{
			name: "invalid",
			as: []*Authorization{
				{URI: "/authz/2"},
			},
			sm: map[string][]protocol.Status{
				"/authz/2": []protocol.Status{protocol.StatusInvalid},
			},

			wantURIs: []string{"/authz/2"},
			err:      fmt.Errorf("authorization validation failed:"),
		},
		{
			name: "pending",
			as: []*Authorization{
				{URI: "/authz/2"},
			},
			sm: map[string][]protocol.Status{
				"/authz/2": []protocol.Status{protocol.StatusPending, protocol.StatusValid},
			},

			wantURIs: []string{"/authz/2", "/authz/2"},
		},
		{
			name: "valid-pending",
			as: []*Authorization{
				{URI: "/authz/2"},
				{URI: "/authz/3"},
			},
			sm: map[string][]protocol.Status{
				"/authz/2": []protocol.Status{protocol.StatusPending, protocol.StatusValid},
				"/authz/3": []protocol.Status{protocol.StatusValid},
			},

			wantURIs: []string{"/authz/3", "/authz/2", "/authz/2"},
		},
	}

	for _, tst := range tsts {
		var uris []string
		counts := map[string]int{}
		ia := &stubIssuingAccount{
			authz: func(uri string) (*Authorization, error) {
				uris = append(uris, uri)
				counts[uri]++
				return &Authorization{Status: tst.sm[uri][counts[uri]-1]}, nil
			},
		}
		err := NewCertificateIssuer(ia).waitAuthorizations(tst.as)
		if !matchError(err, tst.err) {
			t.Errorf("[%s] waitAuthorizations failed: got %v, want prefix %v", tst.name, err, tst.err)
		}
		if !reflect.DeepEqual(uris, tst.wantURIs) {
			t.Errorf("[%s] waitAuthorizations uris: got %v, want %v", tst.name, uris, tst.wantURIs)
		}
	}
}

type stubIssuingAccount struct {
	authzID  func(id Identifier) (*Authorization, error)
	authz    func(uri string) (*Authorization, error)
	validate func(uri string, resp protocol.Response) (protocol.Challenge, error)
	issue    func(csr []byte) (*Certificate, error)
}

func (ia *stubIssuingAccount) AuthorizeIdentity(id Identifier) (*Authorization, error) {
	return ia.authzID(id)
}

func (ia *stubIssuingAccount) Authorization(uri string) (*Authorization, error) {
	return ia.authz(uri)
}

func (ia *stubIssuingAccount) ValidateChallenge(uri string, resp protocol.Response) (protocol.Challenge, error) {
	return ia.validate(uri, resp)
}

func (ia *stubIssuingAccount) IssueCertificate(csr []byte) (*Certificate, error) {
	return ia.issue(csr)
}

type stubSolver struct {
	costs map[protocol.ChallengeType]float64
	resps map[protocol.ChallengeType]protocol.Response
}

func (s *stubSolver) Cost(cs []protocol.Challenge) (float64, error) {
	var ret float64
	for _, c := range cs {
		cost, ok := s.costs[c.GetType()]
		if !ok {
			return 0, ErrUnsolvable
		}
		ret += cost
	}
	return ret, nil
}

func (s *stubSolver) Solve(cs []protocol.Challenge) (resps []protocol.Response, stop func() error, err error) {
	var ret []protocol.Response
	for _, c := range cs {
		resp, ok := s.resps[c.GetType()]
		if !ok {
			return nil, nil, fmt.Errorf("no response for type %q", c.GetType())
		}
		ret = append(ret, resp)
	}
	return ret, func() error { return nil }, nil
}

type byIdentifier []*Authorization

func (as byIdentifier) Len() int { return len(as) }
func (as byIdentifier) Less(i, j int) bool {
	return as[i].Identifier.String() < as[j].Identifier.String()
}
func (as byIdentifier) Swap(i, j int) { as[i], as[j] = as[j], as[i] }

// matchError returns whether err has pat as a prefix.
func matchError(err, pat error) bool {
	if err == nil || pat == nil {
		return err == pat
	}

	return strings.HasPrefix(err.Error(), pat.Error())
}

var (
	// testCSR is a X.509 certificate signing request generated
	// through mustGenerateTestCSR.
	testCSR = []byte{
		48, 129, 251, 48, 129, 168, 2, 1, 0, 48, 24,
		49, 22, 48, 20, 6, 3, 85, 4, 3, 19, 13, 97, 46, 101, 120, 97,
		109, 112, 108, 101, 46, 99, 111, 109, 48, 92, 48, 13, 6, 9,
		42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 75, 0, 48, 72, 2,
		65, 0, 215, 227, 171, 41, 85, 145, 47, 105, 163, 50, 79, 2,
		65, 46, 26, 161, 125, 47, 99, 100, 71, 142, 51, 208, 108, 79,
		130, 194, 212, 167, 92, 57, 176, 246, 151, 181, 52, 29, 241,
		115, 210, 193, 172, 31, 233, 90, 152, 235, 36, 172, 242, 38,
		111, 15, 19, 62, 24, 24, 51, 85, 11, 197, 51, 11, 2, 3, 1, 0,
		1, 160, 43, 48, 41, 6, 9, 42, 134, 72, 134, 247, 13, 1, 9, 14,
		49, 28, 48, 26, 48, 24, 6, 3, 85, 29, 17, 4, 17, 48, 15, 130,
		13, 98, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111,
		109, 48, 11, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 3, 65,
		0, 107, 220, 207, 125, 228, 196, 160, 125, 91, 182, 87, 236,
		231, 192, 9, 158, 1, 41, 23, 34, 83, 230, 183, 6, 185, 170,
		148, 1, 61, 163, 131, 65, 217, 220, 143, 153, 164, 105, 169,
		241, 42, 207, 213, 177, 56, 62, 211, 223, 248, 134, 189, 86,
		46, 114, 169, 48, 93, 107, 188, 112, 80, 84, 38, 123,
	}
)

func mustGenerateTestCSR() []byte {
	cr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "a.example.com",
		},
		DNSNames: []string{"b.example.com"},
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, cr, testJWK.Key)
	if err != nil {
		panic(fmt.Errorf("x509.CreateCertificateRequest failed: %v", err))
	}

	return csr
}
