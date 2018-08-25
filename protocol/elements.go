package protocol

import (
	"encoding/json"
	"gopkg.in/square/go-jose.v2"
)

// Registration describes a reg resource. ACME Section 5.2.
type Registration struct {
	Resource          ResourceType     `json:"resource"`
	Key               *jose.JSONWebKey `json:"key,omitempty"`
	ContactURIs       []string         `json:"contact,omitempty"`
	AgreementURI      string           `json:"agreement,omitempty"`
	AuthorizationsURI string           `json:"authorizations,omitempty"`
	CertificatesURI   string           `json:"certificates,omitempty"`

	// RecoveryKey is a key used to recover an account. ACME Section 6.3.1.
	RecoveryKey *RecoveryKey `json:"recoveryKey,omitempty"`
}

// AuthorizationURIs is a list of authorization URIs. ACME Section 5.2.
type AuthorizationURIs struct {
	Authorizations []string `json:"authorizations"`
}

// CertificateURIs is a list of certificate URIs. ACME Section 5.2.
type CertificateURIs struct {
	Certificates []string `json:"certificates"`
}

// Authorization describes an authz resource. ACME Section 5.3.
type Authorization struct {
	Resource     ResourceType `json:"resource"`
	Identifier   Identifier   `json:"identifier"`
	Status       Status       `json:"status,omitempty"`
	Expires      *Time        `json:"expires,omitempty"`
	Challenges   Challenges   `json:"challenges"`
	Combinations [][]int      `json:"combinations,omitempty"`
}

// Directory describes a directory resource. ACME Section 6.2.
type Directory struct {
	NewReg     string `json:"new-reg"`
	RecoverReg string `json:"recover-reg"`
	NewAuthz   string `json:"new-authz"`
	NewCert    string `json:"new-cert"`
	RevokeCert string `json:"revoke-cert"`
}

// Recovery is an account recovery request. ACME Section 6.3.
// TODO: The ACME spec is not clear whether this is a special
// Registration resource or if it is a Recovery resource.
type Recovery struct {
	Resource    ResourceType      `json:"resource"`
	Method      RecoveryMethod    `json:"method"`
	BaseURI     string            `json:"base"`
	MAC         *JSONWebSignature `json:"mac,omitempty"`
	ContactURIs []string          `json:"contact,omitempty"`
}

// CertificateIssuance describes the new-cert resource; an X.509
// certificate signing request.
type CertificateIssuance struct {
	Resource ResourceType `json:"resource"`
	CSR      DERData      `json:"csr"`
}

// Certificate encapsulates an X.509 certificate.
type Certificate struct {
	Resource    ResourceType `json:"resource"`
	Certificate DERData      `json:"certificate"`
}

// Challenge is the interface implemented by all authorization
// challenge types. Remember to register implementations using
// MustRegisterChallengeType. ACME Section 7.
type Challenge interface {
	GetResource() ResourceType
	GetType() ChallengeType
	GetURI() string
	GetStatus() Status
	GetValidated() *Time
	GetError() *Problem
}

// GenericChallenge is a concrete implementation of Challenge with no
// type-specific information. ACME Section 7.
type GenericChallenge struct {
	Resource  ResourceType  `json:"resource,omitempty"`
	Type      ChallengeType `json:"type,omitempty"`
	URI       string        `json:"uri"`
	Status    Status        `json:"status,omitempty"`
	Validated *Time         `json:"validated,omitempty"`
	Error     *Problem      `json:"error,omitempty"`
}

func (c *GenericChallenge) GetResource() ResourceType { return c.Resource }
func (c *GenericChallenge) GetType() ChallengeType    { return c.Type }
func (c *GenericChallenge) GetURI() string            { return c.URI }
func (c *GenericChallenge) GetStatus() Status         { return c.Status }
func (c *GenericChallenge) GetValidated() *Time       { return c.Validated }
func (c *GenericChallenge) GetError() *Problem        { return c.Error }

// Response is the interface implemented by all challenge response
// types. Unlike challenge types, it requires no registration since
// they are never unmarshaled from JSON in this library. ACME Section 7.
type Response interface {
	GetResource() ResourceType
	GetType() ChallengeType
}

// GenericResponse is a concrete implementation of Response with no
// type-specific information. ACME Section 7.
type GenericResponse struct {
	Resource ResourceType  `json:"resource,omitempty"`
	Type     ChallengeType `json:"type,omitempty"`
}

func (c *GenericResponse) GetResource() ResourceType { return c.Resource }
func (c *GenericResponse) GetType() ChallengeType    { return c.Type }

// Identifier describes a certificate subject. ACME Section 5.3.
type Identifier struct {
	Type  IdentifierType `json:"type"`
	Value string         `json:"value"`
}

// RecoveryKey describes a recover-reg resource. ACME Section 6.3.1.
type RecoveryKey struct {
	Client *jose.JSONWebKey `json:"client,omitempty"`
	Server *jose.JSONWebKey `json:"server,omitempty"`
	Length int              `json:"length,omitempty"`
}

// A Problem is used as an HTTP together with Content-Type
// application/problem+json and describes a high-level server-side
// problem. Defined in
// https://tools.ietf.org/html/draft-ietf-appsawg-http-problem-01, Section 3.1.
type Problem struct {
	Type     ProblemType `json:"type,omitempty"`
	Title    string      `json:"string,omitempty"`
	Status   int         `json:"status,omitempty"`
	Detail   string      `json:"detail"`
	Instance string      `json:"instance,omitempty"`
}

// Challenges is a slice of Challenge that supports JSON encoding
// properly. For unmarshaling to work correctly, you must use
// MustRegisterChallengeType for all possible challenge
// types. Unregistered types will be unmarshaled as GenericChallenge.
type Challenges []Challenge

func (cs Challenges) MarshalJSON() ([]byte, error) {
	return json.Marshal([]Challenge(cs))
}

func (cs *Challenges) UnmarshalJSON(bs []byte) error {
	var acs []anyChallenge

	if err := json.Unmarshal(bs, &acs); err != nil {
		return err
	}

	if len(acs) != 0 {
		// make with capacity zero is not the same as assigning nil.
		// Keeping *cs == nil simplifies testing with reflect.DeepEqual.
		*cs = make(Challenges, 0, len(acs))
	}
	for _, ac := range acs {
		*cs = append(*cs, ac.c)
	}

	return nil
}
