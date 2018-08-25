package protocol

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestRespondTLSALPN01(t *testing.T) {
	c := &TLSALPN01Challenge{
		Resource: ResourceChallenge,
		Type:     ChallengeTLSALPN01,
		URI:      "http://example.com/chal",
		Token:    "token",
	}

	got, err := RespondTLSALPN01(c)
	if err != nil {
		t.Fatalf("RespondTLSALPN01 failed: %v", err)
	}

	want := &TLSALPN01Response{
		Resource: ResourceChallenge,
		Type:     ChallengeTLSALPN01,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RespondTLSALPN01: got %+v, want %+v", got, want)
	}
}

func TestTLSALPN01Challenge(t *testing.T) {
	in := &TLSALPN01Challenge{
		Resource: ResourceChallenge,
		Type:     ChallengeTLSALPN01,
		URI:      "http://example.com/chal",
		Status:   StatusPending,
		Token:    "token",
	}

	bs, err := json.Marshal(Challenge(in))
	if err != nil {
		t.Fatalf("Marshal(%v) failed: %v", in, err)
	}

	if want := `{"resource":"challenge","type":"tls-alpn-01","uri":"http://example.com/chal","status":"pending","token":"token"}`; string(bs) != want {
		t.Fatalf("Marshal(%v): got %q, want %q", in, bs, want)
	}

	var got anyChallenge
	if err := json.Unmarshal(bs, &got); err != nil {
		t.Fatalf("Unmarshal(%v) failed: %v", bs, err)
	}

	if !reflect.DeepEqual(got.c, in) {
		t.Errorf("Unmarshal: got %v, want %v", got, in)
	}
}

func TestTLSALPN01Response(t *testing.T) {
	in := TLSALPN01Response{
		Resource: ResourceChallenge,
		Type:     ChallengeTLSALPN01,
	}

	bs, err := json.Marshal(Response(&in))
	if err != nil {
		t.Fatalf("Marshal(%v) failed: %v", in, err)
	}

	if want := `{"resource":"challenge","type":"tls-alpn-01"}`; string(bs) != want {
		t.Fatalf("Marshal(%v): got %q, want %q", in, bs, want)
	}

	var got TLSALPN01Response
	if err := json.Unmarshal(bs, &got); err != nil {
		t.Fatalf("Unmarshal(%v) failed: %v", bs, err)
	}

	if !reflect.DeepEqual(got, in) {
		t.Errorf("Unmarshal: got %v, want %v", got, in)
	}
}

func TestTLSALPN01Validation(t *testing.T) {
	got, err := TLSALPN01Validation("keyauth", testJWK)
	if err != nil {
		t.Fatalf("TLSALPN01Validation failed: %v", err)
	}

	want := []byte{49, 59, 246, 138, 29, 175, 109, 13, 50, 48, 27, 202, 163, 232, 63, 48, 201, 161, 26, 251, 167, 62, 63, 131, 51, 148, 169, 111, 154, 67, 7, 46}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("TLSALPN01Validation: got %v, want %v", got, want)
	}
}
