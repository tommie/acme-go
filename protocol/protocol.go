// Package protocol provides low-level primitives for working with the
// ACME protocol.
package protocol

const (
	// HTTP headers.
	Link        = "Link"
	ReplayNonce = "Replay-Nonce"
	RetryAfter  = "Retry-After"

	// Link rel values.
	Up = "up"

	// Content types.
	JSON        = "application/json"
	ProblemJSON = "application/problem+json"
	PKIXCert    = "application/pkix-cert"

	RecoveryKeyLabel = "recovery"
)

type ResourceType string

const (
	// Section 5.1.
	ResourceNewReg     ResourceType = "new-reg"
	ResourceRecoverReg ResourceType = "recover-reg"
	ResourceNewAuthz   ResourceType = "new-authz"
	ResourceNewCert    ResourceType = "new-cert"
	ResourceRevokeCert ResourceType = "revoke-cert"
	ResourceReg        ResourceType = "reg"
	ResourceAuthz      ResourceType = "authz"
	ResourceChallenge  ResourceType = "challenge"

	// ResourceCert is unused.
	ResourceCert ResourceType = "cert"
)

type IdentifierType string

const (
	DNS IdentifierType = "dns"
)

type Status string

const (
	// Section 5.3.
	StatusUnknown Status = "unknown"
	StatusPending Status = "pending"
	StatusValid   Status = "valid"
	StatusInvalid Status = "invalid"
	StatusRevoked Status = "revoked"

	// StatusProcessing is unused?
	StatusProcessing Status = "processing"
)

type ChallengeType string

type ProblemType string

const (
	// Section 5.4.
	// TODO: Marked as TODO in draft.
	// Which namespace is it using? urn:acme or urn:acme:error?
	errorNamespace  ProblemType = "urn:acme:error:"
	BadCSR          ProblemType = errorNamespace + "badCSR"
	BadNonce        ProblemType = errorNamespace + "badNonce"
	ConnectionError ProblemType = errorNamespace + "connection"
	DNSSECError     ProblemType = errorNamespace + "dnssec"
	Malformed       ProblemType = errorNamespace + "malformed"
	ServerInternal  ProblemType = errorNamespace + "serverInternal"
	TLSError        ProblemType = errorNamespace + "tls"
	Unauthorized    ProblemType = errorNamespace + "unauthorized"
	UnknownHost     ProblemType = errorNamespace + "unknownHost"
)

type RecoveryMethod string

const (
	// Section 6.4.
	MAC     RecoveryMethod = "mac"
	Contact RecoveryMethod = "contact"
)

// From github.com/letsencrypt/boulder/blob/master/wfe/web-front-end.go
const (
	DirectoryPath  = "/directory"
	NewRegPath     = "/acme/new-reg"
	RecoverRegPath = "/acme/recover-reg"
	RegPath        = "/acme/reg/"
	NewAuthzPath   = "/acme/new-authz"
	AuthzPath      = "/acme/authz/"
	ChallengePath  = "/acme/challenge/"
	NewCertPath    = "/acme/new-cert"
	CertPath       = "/acme/cert/"
	RevokeCertPath = "/acme/revoke-cert"
)
