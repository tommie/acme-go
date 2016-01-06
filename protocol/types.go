package protocol

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/square/go-jose"
)

// DERData is raw DER-encoded data.
type DERData []byte

func (d DERData) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.URLEncoding.EncodeToString([]byte(d)))
}

func (d *DERData) UnmarshalJSON(bs []byte) error {
	var s string
	if err := json.Unmarshal(bs, &s); err != nil {
		return err
	}
	dbs, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	*(*[]byte)(d) = dbs
	return nil
}

// Time is a simple timestamp.
type Time time.Time

func (t Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(t).Format(time.RFC3339))
}

func (t *Time) UnmarshalJSON(bs []byte) error {
	var s string
	if err := json.Unmarshal(bs, &s); err != nil {
		return err
	}

	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}

	*(*time.Time)(t) = ts

	return nil
}

type JSONWebSignature jose.JsonWebSignature

func (s JSONWebSignature) Verify(verificationKey interface{}) ([]byte, error) {
	return jose.JsonWebSignature(s).Verify(verificationKey)
}

func (s JSONWebSignature) MarshalJSON() ([]byte, error) {
	return []byte(jose.JsonWebSignature(s).FullSerialize()), nil
}

func (s *JSONWebSignature) UnmarshalJSON(bs []byte) error {
	ss, err := jose.ParseSigned(string(bs))
	if err != nil {
		return err
	}

	*(*jose.JsonWebSignature)(s) = *ss

	return nil
}

// signJSON encodes the payload as JSON and signs it.
func signJSON(s jose.Signer, payload interface{}) (*JSONWebSignature, error) {
	bs, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	ret, err := s.Sign(bs)
	if err != nil {
		return nil, err
	}

	return (*JSONWebSignature)(ret), nil
}
