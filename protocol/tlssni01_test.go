package protocol

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestRespondTLSSNI01(t *testing.T) {
	c := &TLSSNI01Challenge{
		Resource: ResourceChallenge,
		Type:     ChallengeTLSSNI01,
		URI:      "http://example.com/chal",
		Token:    "token",
	}

	got, err := RespondTLSSNI01(testJWK, c)
	if err != nil {
		t.Fatalf("RespondTLSSNI01 failed: %v", err)
	}

	want := &TLSSNI01Response{
		Resource:         ResourceChallenge,
		Type:             ChallengeTLSSNI01,
		KeyAuthorization: "token.luhDRvWTmOMLRwM2gMkTDdC88jVeIXo9Hm1r_Q6W41Y",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RespondTLSSNI01: got %+v, want %+v", got, want)
	}
}

func TestTLSSNI01Challenge(t *testing.T) {
	in := &TLSSNI01Challenge{
		Resource: ResourceChallenge,
		Type:     ChallengeTLSSNI01,
		URI:      "http://example.com/chal",
		Status:   StatusPending,
		Token:    "token",
		N:        42,
	}

	bs, err := json.Marshal(Challenge(in))
	if err != nil {
		t.Fatalf("Marshal(%v) failed: %v", in, err)
	}

	if want := `{"resource":"challenge","type":"tls-sni-01","uri":"http://example.com/chal","status":"pending","token":"token","n":42}`; string(bs) != want {
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

func TestTLSSNI01Response(t *testing.T) {
	in := TLSSNI01Response{
		Resource:         ResourceChallenge,
		Type:             ChallengeTLSSNI01,
		KeyAuthorization: "key-auth",
	}

	bs, err := json.Marshal(Response(&in))
	if err != nil {
		t.Fatalf("Marshal(%v) failed: %v", in, err)
	}

	if want := `{"resource":"challenge","type":"tls-sni-01","keyAuthorization":"key-auth"}`; string(bs) != want {
		t.Fatalf("Marshal(%v): got %q, want %q", in, bs, want)
	}

	var got TLSSNI01Response
	if err := json.Unmarshal(bs, &got); err != nil {
		t.Fatalf("Unmarshal(%v) failed: %v", bs, err)
	}

	if !reflect.DeepEqual(got, in) {
		t.Errorf("Unmarshal: got %v, want %v", got, in)
	}
}

func TestTLSSNI01Names(t *testing.T) {
	got := TLSSNI01Names("keyauth", 2)
	want := []string{
		"c1b1fd8fabe4017a5f47ab1398fa890b.31d9b5b6bca9ee56bf1a003fd84c4f3b.acme.invalid",
		"d61dda439470857edb7531d028e5ca15.4d5237fa8e5fa7e8485902799e52fe24.acme.invalid",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("TLSSNI01Names: got %v, want %v", got, want)
	}
}
