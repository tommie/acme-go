package protocol

import (
	"encoding/json"
	"reflect"
	"testing"

	"gopkg.in/square/go-jose.v2"
)

func TestRespondPossession01(t *testing.T) {
	c := &Possession01Challenge{
		Resource: ResourceChallenge,
		Type:     ChallengePossession01,
		URI:      "http://example.com/chal",
		Certs:    []DERData{DERData("certdata")},
	}
	v := &Possession01Validation{
		Type:        c.Type,
		Identifiers: []Identifier{{DNS, "example.com"}},
		AccountKey:  *testJWK,
	}

	s, err := jose.NewSigner(testSigningKey, nil)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	got, err := RespondPossession01(s, v, c)
	if err != nil {
		t.Fatalf("RespondPossession01 failed: %v", err)
	}

	want := &Possession01Response{
		Resource: ResourceChallenge,
		Type:     ChallengePossession01,
	}
	if _, err := got.Authorization.Verify(testPublicKey); err != nil {
		t.Errorf("Verify(%+v) failed: %v", got, err)
	}

	// JSONWebSignatures do no unmarshal into the exact same data
	// as the original.
	got.Authorization = JSONWebSignature{}
	want.Authorization = JSONWebSignature{}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RespondPossession01: got %+v, want %+v", got, want)
	}
}

func TestPossession01Challenge(t *testing.T) {
	in := &Possession01Challenge{
		Resource: ResourceChallenge,
		Type:     ChallengePossession01,
		URI:      "http://example.com/chal",
		Status:   StatusPending,
		Certs:    []DERData{DERData("hello world")},
	}

	bs, err := json.Marshal(Challenge(in))
	if err != nil {
		t.Fatalf("Marshal(%v) failed: %v", in, err)
	}

	if want := `{"resource":"challenge","type":"proofOfPossession-01","uri":"http://example.com/chal","status":"pending","certs":["aGVsbG8gd29ybGQ="]}`; string(bs) != want {
		t.Fatalf("Marshal(%v): got %q, want %q", in, bs, want)
	}

	var out anyChallenge
	if err := json.Unmarshal(bs, &out); err != nil {
		t.Fatalf("Unmarshal(%v) failed: %v", bs, err)
	}

	if !reflect.DeepEqual(out.c, in) {
		t.Errorf("Unmarshal: got %v, want %v", out, in)
	}
}

func TestPossession01Response(t *testing.T) {
	in := Possession01Response{
		Resource: ResourceChallenge,
		Type:     ChallengePossession01,
	}

	s, err := jose.NewSigner(testSigningKey, &jose.SignerOptions{EmbedJWK: true})
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	sign, err := signJSON(s, []byte{})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	in.Authorization = *sign

	bs, err := json.Marshal(Response(&in))
	if err != nil {
		t.Fatalf("Marshal(%v) failed: %v", in, err)
	}

	if want := `{"resource":"challenge","type":"proofOfPossession-01","authorization":{"payload":"IiI","protected":"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiMS1PcktWV1JMMm1qTWs4Q1FTNGFvWDB2WTJSSGpqUFFiRS1Dd3RTblhEbXc5cGUxTkIzeGM5TEJyQl9wV3BqckpLenlKbThQRXo0WUdETlZDOFV6Q3ciLCJlIjoiQVFBQiJ9fQ","signature":"aP5V6W1NP6mAXA0RXRugwunE-Fm-vkSC4YepjLIBsYszqsbJcTcQBODfC76qMNmmoHahhsoOTF_wDM183FAwdw"}}`; string(bs) != want {
		t.Fatalf("Marshal(%v): got %q, want %q", in, bs, want)
	}

	var got Possession01Response
	if err := json.Unmarshal(bs, &got); err != nil {
		t.Fatalf("Unmarshal(%v) failed: %v", bs, err)
	}

	if _, err := got.Authorization.Verify(testPublicKey); err != nil {
		t.Errorf("Verify(%+v) failed: %v", got, err)
	}

	// JSONWebSignatures do no unmarshal into the exact same data
	// as the original.
	in.Authorization = JSONWebSignature{}
	got.Authorization = JSONWebSignature{}
	if !reflect.DeepEqual(got, in) {
		t.Errorf("Unmarshal: got %v, want %v", got, in)
	}
}
