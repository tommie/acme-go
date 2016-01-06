package protocol

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestChallengesJSON(t *testing.T) {
	in := Challenges{
		&HTTP01Challenge{
			Resource: ResourceChallenge,
			Type:     ChallengeHTTP01,
		},
		&DNS01Challenge{
			Resource: ResourceChallenge,
			Type:     ChallengeDNS01,
		},
	}

	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal(%v) failed: %v", in, err)
	}

	if want := `[{"resource":"challenge","type":"http-01","uri":"","token":""},{"resource":"challenge","type":"dns-01","uri":"","token":""}]`; string(bs) != want {
		t.Fatalf("Marshal(%v): got %q, want %q", in, bs, want)
	}

	var out Challenges
	if err := json.Unmarshal(bs, &out); err != nil {
		t.Fatalf("Unmarshal(%v) failed: %v", bs, err)
	}

	if !reflect.DeepEqual(out, in) {
		t.Errorf("Unmarshal: got %v, want %v", out, in)
	}
}
