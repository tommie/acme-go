package protocol

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestRespondDNS01(t *testing.T) {
	c := &DNS01Challenge{
		Resource: ResourceChallenge,
		Type:     ChallengeDNS01,
		URI:      "http://example.com/chal",
		Token:    "token",
	}

	got, err := RespondDNS01(testJWK, c)
	if err != nil {
		t.Fatalf("RespondDNS01 failed: %v", err)
	}

	want := &DNS01Response{
		Resource:         ResourceChallenge,
		Type:             ChallengeDNS01,
		KeyAuthorization: "token.luhDRvWTmOMLRwM2gMkTDdC88jVeIXo9Hm1r_Q6W41Y=",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RespondDNS01: got %+v, want %+v", got, want)
	}
}

func TestDNS01Challenge(t *testing.T) {
	in := &DNS01Challenge{
		Resource: ResourceChallenge,
		Type:     ChallengeDNS01,
		URI:      "http://example.com/chal",
		Status:   StatusPending,
		Token:    "token",
	}

	bs, err := json.Marshal(Challenge(in))
	if err != nil {
		t.Fatalf("Marshal(%v) failed: %v", in, err)
	}

	if want := `{"resource":"challenge","type":"dns-01","uri":"http://example.com/chal","status":"pending","token":"token"}`; string(bs) != want {
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

func TestDNS01Response(t *testing.T) {
	in := DNS01Response{
		Resource:         ResourceChallenge,
		Type:             ChallengeDNS01,
		KeyAuthorization: "key-auth",
	}

	bs, err := json.Marshal(Response(&in))
	if err != nil {
		t.Fatalf("Marshal(%v) failed: %v", in, err)
	}

	if want := `{"resource":"challenge","type":"dns-01","keyAuthorization":"key-auth"}`; string(bs) != want {
		t.Fatalf("Marshal(%v): got %q, want %q", in, bs, want)
	}

	var got DNS01Response
	if err := json.Unmarshal(bs, &got); err != nil {
		t.Fatalf("Unmarshal(%v) failed: %v", bs, err)
	}

	if !reflect.DeepEqual(got, in) {
		t.Errorf("Unmarshal: got %v, want %v", got, in)
	}
}
