package protocol

import (
	"fmt"

	"github.com/square/go-jose"
)

const (
	ChallengePossession01 ChallengeType = "proofOfPossession-01"
)

// RespondPossession01 creates a response based on a challenge and a
// signer using the old certificate key.
func RespondPossession01(s jose.Signer, v *Possession01Validation, c *Possession01Challenge) (*Possession01Response, error) {
	if c.Resource != ResourceChallenge {
		return nil, fmt.Errorf("unexpected resource type: %s", c.Resource)
	}
	if c.Type != ChallengePossession01 {
		return nil, fmt.Errorf("unexpected challenge type: %s", c.Type)
	}

	a, err := signJSON(s, v)
	if err != nil {
		return nil, err
	}

	return &Possession01Response{c.Resource, c.Type, *a}, nil
}

type Possession01Challenge struct {
	Resource  ResourceType  `json:"resource,omitempty"`
	Type      ChallengeType `json:"type,omitempty"`
	URI       string        `json:"uri"`
	Status    Status        `json:"status,omitempty"`
	Validated *Time         `json:"validated,omitempty"`
	Error     *Problem      `json:"error,omitempty"`
	Certs     []DERData     `json:"certs"`
}

func (c *Possession01Challenge) GetResource() ResourceType { return c.Resource }
func (c *Possession01Challenge) GetType() ChallengeType    { return c.Type }
func (c *Possession01Challenge) GetURI() string            { return c.URI }
func (c *Possession01Challenge) GetStatus() Status         { return c.Status }
func (c *Possession01Challenge) GetValidated() *Time       { return c.Validated }
func (c *Possession01Challenge) GetError() *Problem        { return c.Error }

// Possession01Validation is the payload of Possession01Response.Authorization.
type Possession01Validation struct {
	Type        ChallengeType   `json:"type"`
	Identifiers []Identifier    `json:"identifiers"`
	AccountKey  jose.JsonWebKey `json:"accountKey"`
}

type Possession01Response struct {
	Resource      ResourceType     `json:"resource,omitempty"`
	Type          ChallengeType    `json:"type,omitempty"`
	Authorization JSONWebSignature `json:"authorization"`
}

func (c *Possession01Response) GetResource() ResourceType { return c.Resource }
func (c *Possession01Response) GetType() ChallengeType    { return c.Type }

func init() {
	MustRegisterChallengeType(ChallengePossession01, &Possession01Challenge{})
}
