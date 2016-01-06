package protocol

import (
	"fmt"

	"github.com/square/go-jose"
)

const (
	ChallengeHTTP01 ChallengeType = "http-01"
	HTTP01BasePath  string        = "/.well-known/acme-challenge"
)

// RespondHTTP01 creates a response to a http-01 challenge given an
// account key.
func RespondHTTP01(key *jose.JsonWebKey, c *HTTP01Challenge) (*HTTP01Response, error) {
	if c.Resource != ResourceChallenge {
		return nil, fmt.Errorf("unexpected resource type: %s", c.Resource)
	}
	if c.Type != ChallengeHTTP01 {
		return nil, fmt.Errorf("unexpected challenge type: %s", c.Type)
	}

	ka, err := KeyAuthz(c.Token, key)
	if err != nil {
		return nil, err
	}

	return &HTTP01Response{c.Resource, c.Type, ka}, nil
}

type HTTP01Challenge struct {
	Resource  ResourceType  `json:"resource,omitempty"`
	Type      ChallengeType `json:"type,omitempty"`
	URI       string        `json:"uri"`
	Status    Status        `json:"status,omitempty"`
	Validated *Time         `json:"validated,omitempty"`
	Error     *Problem      `json:"error,omitempty"`
	Token     string        `json:"token"`
}

func (c *HTTP01Challenge) GetResource() ResourceType { return c.Resource }
func (c *HTTP01Challenge) GetType() ChallengeType    { return c.Type }
func (c *HTTP01Challenge) GetURI() string            { return c.URI }
func (c *HTTP01Challenge) GetStatus() Status         { return c.Status }
func (c *HTTP01Challenge) GetValidated() *Time       { return c.Validated }
func (c *HTTP01Challenge) GetError() *Problem        { return c.Error }

type HTTP01Response struct {
	Resource         ResourceType  `json:"resource,omitempty"`
	Type             ChallengeType `json:"type,omitempty"`
	KeyAuthorization string        `json:"keyAuthorization"`
}

func (c *HTTP01Response) GetResource() ResourceType { return c.Resource }
func (c *HTTP01Response) GetType() ChallengeType    { return c.Type }

func init() {
	MustRegisterChallengeType(ChallengeHTTP01, &HTTP01Challenge{})
}
