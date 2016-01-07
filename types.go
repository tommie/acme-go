package acme

import (
	"fmt"
	"net/http"
	"time"

	"github.com/tommie/acme-go/protocol"
)

type Authorization struct {
	protocol.Authorization

	Status     protocol.Status
	Identifier Identifier
	URI        string
	RetryAfter time.Duration
}

func newAuthorization(authz *protocol.Authorization, resp *http.Response) (*Authorization, error) {
	st := authz.Status
	if st == "" {
		// Missing status value means "pending". ACME spec Sec. 5.3.
		st = protocol.StatusPending
	}

	id, err := newIdentifier(authz.Identifier)
	if err != nil {
		return nil, err
	}

	uri, err := resp.Location()
	if err == http.ErrNoLocation {
		// Fall back to request URI.
		// TODO: Check that the request wasn't for a new authorization.
		uri = resp.Request.URL
	} else if err != nil {
		return nil, err
	}

	ra, _ := retryAfter(resp.Header, 0)

	return &Authorization{
		Authorization: *authz,
		Status:        st,
		Identifier:    id,
		URI:           uri.String(),
		RetryAfter:    ra,
	}, nil
}

type Certificate struct {
	Bytes      []byte
	URI        string
	IssuerURIs []string
}

type Identifier interface {
	Protocol() *protocol.Identifier
	String() string
}

type DNSIdentifier string

func (u DNSIdentifier) Protocol() *protocol.Identifier {
	return &protocol.Identifier{Type: protocol.DNS, Value: string(u)}
}

func (i DNSIdentifier) String() string {
	return "dns:" + string(i)
}

func newIdentifier(id protocol.Identifier) (Identifier, error) {
	switch id.Type {
	case protocol.DNS:
		return DNSIdentifier(id.Value), nil

	default:
		return nil, fmt.Errorf("unknown identifier type %q in %v", id.Type, id)
	}
}
