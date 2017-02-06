package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/square/go-jose"
)

const (
	ChallengeDNS01 ChallengeType = "dns-01"
	DNS01Label     string        = "_acme-challenge"
)

func RespondDNS01(key *jose.JsonWebKey, c *DNS01Challenge) (*DNS01Response, error) {
	if c.Resource != ResourceChallenge {
		return nil, fmt.Errorf("unexpected resource type: %s", c.Resource)
	}
	if c.Type != ChallengeDNS01 {
		return nil, fmt.Errorf("unexpected challenge type: %s", c.Type)
	}

	ka, err := KeyAuthz(c.Token, key)
	if err != nil {
		return nil, err
	}

	return &DNS01Response{c.Resource, c.Type, ka}, nil
}

// DNS01TXTRecord returns a TXT record data string based on generated key
// authorization as created by RespondDNS01.
func DNS01TXTRecord(keyAuthz string) string {
	h := sha256.New()
	h.Write([]byte(keyAuthz))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

type DNS01Challenge struct {
	Resource  ResourceType  `json:"resource,omitempty"`
	Type      ChallengeType `json:"type,omitempty"`
	URI       string        `json:"uri"`
	Status    Status        `json:"status,omitempty"`
	Validated *Time         `json:"validated,omitempty"`
	Error     *Problem      `json:"error,omitempty"`
	Token     string        `json:"token"`
}

func (c *DNS01Challenge) GetResource() ResourceType { return c.Resource }
func (c *DNS01Challenge) GetType() ChallengeType    { return c.Type }
func (c *DNS01Challenge) GetURI() string            { return c.URI }
func (c *DNS01Challenge) GetStatus() Status         { return c.Status }
func (c *DNS01Challenge) GetValidated() *Time       { return c.Validated }
func (c *DNS01Challenge) GetError() *Problem        { return c.Error }

type DNS01Response struct {
	Resource         ResourceType  `json:"resource,omitempty"`
	Type             ChallengeType `json:"type,omitempty"`
	KeyAuthorization string        `json:"keyAuthorization"`
}

func (c *DNS01Response) GetResource() ResourceType { return c.Resource }
func (c *DNS01Response) GetType() ChallengeType    { return c.Type }

func init() {
	MustRegisterChallengeType(ChallengeDNS01, &DNS01Challenge{}, &DNS01Response{})
}
