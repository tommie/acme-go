package protocol

import (
	"fmt"

	"github.com/square/go-jose"
)

const (
	ChallengeTLSSNI01 ChallengeType = "tls-sni-01"
	TLSSNI01Suffix    string        = "acme.invalid"
)

// RespondTLSSNI01 creates a response based on a challenge and an
// account key.
func RespondTLSSNI01(key *jose.JsonWebKey, c *TLSSNI01Challenge) (*TLSSNI01Response, error) {
	if c.Resource != ResourceChallenge {
		return nil, fmt.Errorf("unexpected resource type: %s", c.Resource)
	}
	if c.Type != ChallengeTLSSNI01 {
		return nil, fmt.Errorf("unexpected challenge type: %s", c.Type)
	}

	ka, err := KeyAuthz(c.Token, key)
	if err != nil {
		return nil, err
	}

	return &TLSSNI01Response{c.Resource, c.Type, ka}, nil
}

type TLSSNI01Challenge struct {
	Resource  ResourceType  `json:"resource,omitempty"`
	Type      ChallengeType `json:"type,omitempty"`
	URI       string        `json:"uri"`
	Status    Status        `json:"status,omitempty"`
	Validated *Time         `json:"validated,omitempty"`
	Error     *Problem      `json:"error,omitempty"`
	Token     string        `json:"token"`
	N         int           `json:"n"`
}

func (c *TLSSNI01Challenge) GetResource() ResourceType { return c.Resource }
func (c *TLSSNI01Challenge) GetType() ChallengeType    { return c.Type }
func (c *TLSSNI01Challenge) GetURI() string            { return c.URI }
func (c *TLSSNI01Challenge) GetStatus() Status         { return c.Status }
func (c *TLSSNI01Challenge) GetValidated() *Time       { return c.Validated }
func (c *TLSSNI01Challenge) GetError() *Problem        { return c.Error }

type TLSSNI01Response struct {
	Resource         ResourceType  `json:"resource,omitempty"`
	Type             ChallengeType `json:"type,omitempty"`
	KeyAuthorization string        `json:"keyAuthorization"`
}

func (c *TLSSNI01Response) GetResource() ResourceType { return c.Resource }
func (c *TLSSNI01Response) GetType() ChallengeType    { return c.Type }

func init() {
	MustRegisterChallengeType(ChallengeTLSSNI01, &TLSSNI01Challenge{})
}
