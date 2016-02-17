package protocol

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/square/go-jose"
)

// KeyAuthz returns the key authorization string for a challenge token
// and account key. Section 7.1.
func KeyAuthz(tok string, key *jose.JsonWebKey) (string, error) {
	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	return tok + "." + RawURLEncodeToString(tp), nil
}

// RawURLEncodeToString emulates base64.RawURLEncoding.EncodeToString
// found in go1.5.
func RawURLEncodeToString(bs []byte) string {
	ret := base64.URLEncoding.EncodeToString(bs)
	return strings.TrimRight(ret, "=")
}

var (
	// challengeTypes holds registered challenge types.
	challengeTypes = map[ChallengeType]reflect.Type{}
	// responseTypes holds registered response types.
	responseTypes = map[ChallengeType]reflect.Type{}
	// ctMu protects challengeTypes.
	ctMu sync.Mutex
)

// MustRegisterChallengeType register a challenge struct for a given
// type. This is needed to unmarshal challenges into appropriate
// types. Should be called in init functions of files defining
// challenges.
func MustRegisterChallengeType(name ChallengeType, c Challenge, r Response) {
	ctMu.Lock()
	defer ctMu.Unlock()

	if t, ok := challengeTypes[name]; ok {
		panic(fmt.Errorf("challenge type %q already registered: %v", name, t))
	}

	challengeTypes[name] = reflect.TypeOf(c).Elem()
	responseTypes[name] = reflect.TypeOf(r).Elem()
}

// newChallenge returns a zero value of the registered challenge type.
func newChallenge(name ChallengeType) Challenge {
	ctMu.Lock()
	defer ctMu.Unlock()

	t, ok := challengeTypes[name]
	if !ok {
		return nil
	}

	return reflect.New(t).Interface().(Challenge)
}

// newResponse returns a zero value of the registered response type.
func newResponse(name ChallengeType) Response {
	ctMu.Lock()
	defer ctMu.Unlock()

	t, ok := responseTypes[name]
	if !ok {
		return nil
	}

	return reflect.New(t).Interface().(Response)
}

// anyChallenge wraps any (registered) type of Challenge. Used to
// decode JSON into appropriate types.
type anyChallenge struct {
	c Challenge
}

func (c anyChallenge) MarshalJSON() ([]byte, error) {
	if c.c == nil {
		return nil, fmt.Errorf("attempt to marshal nil challenge")
	}
	if c.c.GetType() == "" {
		return nil, fmt.Errorf("challenge with no type set: %+v", c.c)
	}

	return json.Marshal(c.c)
}

func (c *anyChallenge) UnmarshalJSON(bs []byte) error {
	var cb challengeBase
	if err := json.Unmarshal(bs, &cb); err != nil {
		return err
	}

	c.c = newChallenge(cb.Type)
	if c.c == nil {
		c.c = &GenericChallenge{}
	}

	return json.Unmarshal(bs, c.c)
}

// challengeBase describes a challenge with just enough values to
// determine the type of challenge.
type challengeBase struct {
	Resource ResourceType  `json:"resource"`
	Type     ChallengeType `json:"type"`
}

// anyResponse wraps any (registered) type of Response. Used to
// decode JSON into appropriate types.
type anyResponse struct {
	r Response
}

func (r anyResponse) MarshalJSON() ([]byte, error) {
	if r.r == nil {
		return nil, fmt.Errorf("attempt to marshal nil response")
	}
	if r.r.GetType() == "" {
		return nil, fmt.Errorf("response with no type set: %+v", r.r)
	}

	return json.Marshal(r.r)
}

func (r *anyResponse) UnmarshalJSON(bs []byte) error {
	var cb responseBase
	if err := json.Unmarshal(bs, &cb); err != nil {
		return err
	}

	r.r = newResponse(cb.Type)
	if r.r == nil {
		r.r = &GenericResponse{}
	}

	return json.Unmarshal(bs, r.r)
}

// responseBase describes a challenge with just enough values to
// determine the type of response.
type responseBase struct {
	Resource ResourceType  `json:"resource"`
	Type     ChallengeType `json:"type"`
}
