package acme

import (
	"reflect"
	"strings"
	"testing"

	"github.com/tommie/acme-go/protocol"
)

func TestClientAccountRegisterAccount(t *testing.T) {
	_, hts := newFakeACMEServer()
	defer hts.Close()

	a, reg, err := RegisterAccount(hts.URL+protocol.DirectoryPath, testJWK.Key, WithContactURIs("mailto:acme@example.com"))
	if err != nil {
		t.Fatalf("RegisterAccount(WithContactURIs) failed: %v", err)
	}
	if want := []string{"mailto:acme@example.com"}; !reflect.DeepEqual(reg.ContactURIs, want) {
		t.Errorf("RegisterAccount(WithContactURIs) ContactURIs: got %v, want %v", reg.ContactURIs, want)
	}
	if want := "/reg/1"; !strings.HasSuffix(reg.URI, want) {
		t.Errorf("RegisterAccount(WithContactURIs) reg.URI: got %v, want suffix %v", reg.URI, want)
	}
	if want := "/reg/1"; !strings.HasSuffix(a.URI, want) {
		t.Errorf("RegisterAccount(WithContactURIs) a.URI: got %v, want suffix %v", a.URI, want)
	}
}
