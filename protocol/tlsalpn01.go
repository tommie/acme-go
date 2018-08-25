package protocol

import (
	"crypto/sha256"
	"fmt"

	"gopkg.in/square/go-jose.v2"
)

const (
	ChallengeTLSALPN01 ChallengeType = "tls-alpn-01"
)

// RespondTLSALPN01 creates a response based on a challenge.
func RespondTLSALPN01(c *TLSALPN01Challenge) (*TLSALPN01Response, error) {
	if c.Resource != ResourceChallenge {
		return nil, fmt.Errorf("unexpected resource type: %s", c.Resource)
	}
	if c.Type != ChallengeTLSALPN01 {
		return nil, fmt.Errorf("unexpected challenge type: %s", c.Type)
	}

	return &TLSALPN01Response{c.Resource, c.Type}, nil
}

func TLSALPN01Validation(token string, key *jose.JSONWebKey) ([]byte, error) {
	ka, err := KeyAuthz(token, key)
	if err != nil {
		return nil, err
	}
	ba := sha256.Sum256([]byte(ka))
	return ba[:], nil
}

type TLSALPN01Challenge struct {
	Resource  ResourceType  `json:"resource,omitempty"`
	Type      ChallengeType `json:"type,omitempty"`
	URI       string        `json:"uri"`
	Status    Status        `json:"status,omitempty"`
	Validated *Time         `json:"validated,omitempty"`
	Error     *Problem      `json:"error,omitempty"`
	Token     string        `json:"token"`
}

func (c *TLSALPN01Challenge) GetResource() ResourceType { return c.Resource }
func (c *TLSALPN01Challenge) GetType() ChallengeType    { return c.Type }
func (c *TLSALPN01Challenge) GetURI() string            { return c.URI }
func (c *TLSALPN01Challenge) GetStatus() Status         { return c.Status }
func (c *TLSALPN01Challenge) GetValidated() *Time       { return c.Validated }
func (c *TLSALPN01Challenge) GetError() *Problem        { return c.Error }

type TLSALPN01Response struct {
	Resource ResourceType  `json:"resource,omitempty"`
	Type     ChallengeType `json:"type,omitempty"`
}

func (c *TLSALPN01Response) GetResource() ResourceType { return c.Resource }
func (c *TLSALPN01Response) GetType() ChallengeType    { return c.Type }

func init() {
	MustRegisterChallengeType(ChallengeTLSALPN01, &TLSALPN01Challenge{}, &TLSALPN01Response{})
}
