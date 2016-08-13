package acme

import (
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/tommie/acme-go/protocol"
)

var (
	ErrCanceled   = errors.New("operation canceled")
	ErrUnsolvable = errors.New("unsolvable challenge")
)

// An AuthorizationError wraps another error and adds information about what
// authorizations were being attempted.
type AuthorizationError struct {
	Err            error
	Authorizations []*Authorization
}

func (e *AuthorizationError) Error() string {
	var auths []string
	for _, a := range e.Authorizations {
		auth := fmt.Sprintf("Authorization of %s, one of: ", a.Identifier)
		for _, comb := range a.Combinations {
			var chals []string
			for _, i := range comb {
				chals = append(chals, string(a.Challenges[i].GetType()))
			}
			auth += fmt.Sprintf("(%s)", strings.Join(chals, ", "))
		}
		auths = append(auths, auth)
	}
	return fmt.Sprintf("%s (authorizations %s)", e.Err, strings.Join(auths, ", "))
}

// A CertificateIssuer can authorize and issue certificates in one
// go. A currently running issuer can be canceled.
type CertificateIssuer struct {
	ia IssuingAccount

	cancel chan struct{}
}

func NewCertificateIssuer(ia IssuingAccount) *CertificateIssuer {
	return &CertificateIssuer{ia, make(chan struct{})}
}

// AuthorizeAndIssue issues a certificate based on a signing request
// after completing any necessary identity authorization
// challenges. The certificate will be tied to the issuing account on
// success. The solvers are used to solve challenges. Solvers are
// chosen to minimize the solver cost. Note that the function does not
// care about the cost unit, but it needs to be consistent across all
// solvers.
//
// If one solver instance is used for multiple types, and the server
// requests solving all types, they may be lumped together in the same
// call to Solve.
func (ci *CertificateIssuer) AuthorizeAndIssue(csr []byte, s Solver) (*Certificate, error) {
	as, err := ci.authorizeIdentities(csr)
	if err != nil {
		return nil, err
	}

	if len(as) > 0 {
		cs, err := bestChallenges(s, as)
		if err != nil {
			return nil, &AuthorizationError{err, as}
		}

		stop, err := ci.startSolver(s, cs)
		if err != nil {
			return nil, err
		}
		defer stop()

		if err := ci.waitAuthorizations(as); err != nil {
			return nil, err
		}
	}

	return ci.ia.IssueCertificate(csr)
}

// authorizeIdentities requests new challenges for the given X.509
// CSR. Only pending authorizations are returned. If any authorization
// is invalid, the call fails.
func (ci *CertificateIssuer) authorizeIdentities(csr []byte) ([]*Authorization, error) {
	pcsr, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, err
	}

	// De-duplicate names.
	names := make(map[string]Identifier, 1+len(pcsr.DNSNames))
	for _, n := range append([]string{pcsr.Subject.CommonName}, pcsr.DNSNames...) {
		names[n] = DNSIdentifier(n)
	}

	var ret []*Authorization
	for n, id := range names {
		if ci.isCanceled() {
			return nil, ErrCanceled
		}

		// TODO: Check for existing valid (and pending) authorizations first?
		// Whether an existing authz is useful or not depends on how long it
		// will remain useful, and we don't have that information.
		a, err := ci.ia.AuthorizeIdentity(id)
		if err != nil {
			return nil, err
		}
		switch a.Status {
		case protocol.StatusPending:
			ret = append(ret, a)

		case protocol.StatusInvalid:
			return nil, fmt.Errorf("authorization invalid for %q", n)

		case protocol.StatusValid:
			// nothing

		default:
			return nil, fmt.Errorf("unknown authorization status for %q: %v", n, a.Status)
		}
	}

	return ret, nil
}

// bestChallenges picks challenges with lowest cost to solve.
func bestChallenges(s Solver, as []*Authorization) ([]protocol.Challenge, error) {
	var ret []protocol.Challenge
	for _, a := range as {
		cs, err := bestCombination(s, a)
		if err != nil {
			return nil, err
		}
		ret = append(ret, cs...)
	}

	// We have combined challenges. Make sure we can solve them together.
	_, err := s.Cost(ret)
	return ret, err
}

// bestCombination finds the challenge combination with a lowest
// cost. Returns ErrUnsolvable if no solvable combination exists.
func bestCombination(s Solver, a *Authorization) ([]protocol.Challenge, error) {
	var errs []error
	var ret []protocol.Challenge
	bestCost := math.Inf(1)

	for _, cis := range a.Combinations {
		var cs []protocol.Challenge
		for _, ci := range cis {
			cs = append(cs, a.Challenges[ci])
		}
		cost, err := s.Cost(cs)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		if cost < bestCost {
			// Replace the previous best combination.
			bestCost = cost
			ret = cs
		}
	}

	if math.IsInf(bestCost, 1) {
		if len(errs) > 0 {
			return nil, errs[len(errs)-1]
		}
		return nil, ErrUnsolvable
	}

	return ret, nil
}

// startSolver instantiates the solver and informs the ACME server.
func (ci *CertificateIssuer) startSolver(s Solver, cs []protocol.Challenge) (func() error, error) {
	resps, stop, err := s.Solve(cs)
	if err != nil {
		return nil, err
	}
	errStop := stop
	defer func() {
		errStop()
	}()

	if len(resps) != len(cs) {
		return nil, fmt.Errorf("solver was given %d challenges, but returned %d responses (the solver code is broken)", len(cs), len(resps))
	}

	// Tell the ACME server the challenge was accepted.
	for i, ch := range cs {
		if ci.isCanceled() {
			return nil, ErrCanceled
		}

		ch, err = ci.ia.ValidateChallenge(ch.GetURI(), resps[i])
		if err != nil {
			return nil, err
		}
		if ch.GetStatus() == protocol.StatusInvalid {
			return nil, fmt.Errorf("challenge validation failed: %+v", ch)
		}
	}

	errStop = func() error { return nil }
	return stop, nil
}

// waitAuthorizations waits for authorization requests to complete.
func (ci *CertificateIssuer) waitAuthorizations(as []*Authorization) error {
	// It doesn't matter in which order we do this since all of
	// them must complete. So we think of rem as a stack, for
	// simplicity.
	for len(as) != 0 {
		if ci.isCanceled() {
			return ErrCanceled
		}

		a, err := ci.ia.Authorization(as[len(as)-1].URI)
		if err != nil {
			return err
		}
		switch a.Status {
		case protocol.StatusValid:
			as = as[:len(as)-1]
			a.RetryAfter = 0

		case protocol.StatusInvalid:
			return fmt.Errorf("authorization validation failed: %+v", a)
		}

		select {
		case <-time.After(a.RetryAfter):
			break

		case <-ci.cancel:
			return ErrCanceled
		}
	}

	return nil
}

// Cancel stops any running invocation of AuthorizeAndIssue and causes
// new invocations to fail early. A canceled issuer should not be reused.
func (ci *CertificateIssuer) Cancel() {
	close(ci.cancel)
}

func (ci *CertificateIssuer) isCanceled() bool {
	select {
	case <-ci.cancel:
		return true

	default:
		return false
	}
}

// An IssuingAccount is an interface to something that can issue ACME
// certificates given a registered account. A ClientAccount fulfills
// this interface.
type IssuingAccount interface {
	AuthorizeIdentity(id Identifier) (*Authorization, error)
	Authorization(uri string) (*Authorization, error)
	ValidateChallenge(uri string, resp protocol.Response) (protocol.Challenge, error)
	IssueCertificate(csr []byte) (*Certificate, error)
}

// Solver is a way to produce responses to one or more
// challenges. Solver object functions must be concurrency-safe.
type Solver interface {
	// Cost describes the cost to solve the set of challenges. The
	// returned cost is a number in some (consistent) unit. It
	// should be fast to evaluate the cost. The function should
	// return ErrUnsolvable if any challenge cannot be solved.
	Cost([]protocol.Challenge) (float64, error)

	// Solve is a function that starts a solver for some
	// challenges. The returned stop function will be called to
	// stop the solver and release resources. The same solver can
	// be used to solve multiple challenges at once. Each returned
	// response must correspond to the challenge of the same
	// index and len(ch) == len(resps).
	//
	// If err != nil, the stop function must not be called.
	Solve([]protocol.Challenge) (resps []protocol.Response, stop func() error, err error)
}
