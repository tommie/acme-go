package protocol

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/square/go-jose"
)

func TestDERData(t *testing.T) {
	in := DERData("hello world")

	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal(%v) failed: %v", in, err)
	}

	if want := `"aGVsbG8gd29ybGQ="`; string(bs) != want {
		t.Fatalf("Marshal(%v): got %q, want %q", in, bs, want)
	}

	var out DERData
	if err := json.Unmarshal(bs, &out); err != nil {
		t.Fatalf("Unmarshal(%v) failed: %v", bs, err)
	}

	if !reflect.DeepEqual(out, in) {
		t.Errorf("Unmarshal: got %v, want %v", out, in)
	}
}

func TestTime(t *testing.T) {
	in := Time(time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC))

	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal(%v) failed: %v", in, err)
	}

	if want := `"2006-01-02T15:04:05Z"`; string(bs) != want {
		t.Fatalf("Marshal(%v): got %q, want %q", in, bs, want)
	}

	var out Time
	if err := json.Unmarshal(bs, &out); err != nil {
		t.Fatalf("Unmarshal(%v) failed: %v", bs, err)
	}

	if !reflect.DeepEqual(out, in) {
		t.Errorf("Unmarshal: got %v, want %v", out, in)
	}
}

func TestJSONWebSignature(t *testing.T) {
	s, err := jose.NewSigner(jose.RS256, testJWK.Key)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	// Also tests signJSON.
	in, err := signJSON(s, []byte{})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	bs, err := json.Marshal((*JSONWebSignature)(in))
	if err != nil {
		t.Fatalf("Marshal(%v) failed: %v", in, err)
	}

	if want := `{"payload":"IiI","protected":"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiMS1PcktWV1JMMm1qTWs4Q1FTNGFvWDB2WTJSSGpqUFFiRS1Dd3RTblhEbXc5cGUxTkIzeGM5TEJyQl9wV3BqckpLenlKbThQRXo0WUdETlZDOFV6Q3ciLCJlIjoiQVFBQiJ9fQ","signature":"aP5V6W1NP6mAXA0RXRugwunE-Fm-vkSC4YepjLIBsYszqsbJcTcQBODfC76qMNmmoHahhsoOTF_wDM183FAwdw"}`; string(bs) != want {
		t.Fatalf("Marshal(%v): got %q, want %q", in, bs, want)
	}

	var got JSONWebSignature
	if err := json.Unmarshal(bs, &got); err != nil {
		t.Fatalf("Unmarshal(%v) failed: %v", bs, err)
	}

	// JsonWebSignatures do no unmarshal into the exact same data
	// as the original.
	if _, err := got.Verify(testPublicKey); err != nil {
		t.Errorf("Verify(%+v) failed: %v", got, err)
	}
}
