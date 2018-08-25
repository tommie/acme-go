package protocol

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"gopkg.in/square/go-jose.v2"
)

// requestBodyLimit is the maximum number of bytes we read from a
// request body. This is for basic DoS protection.
const requestBodyLimit int = 1 << 20

// A NonceSource is something that can generate and verify replay nonces.
type NonceSource interface {
	jose.NonceSource

	// Verify returns an error if the provided nonce was not issued by
	// this nonce source, or if it has already been used in a call to
	// Verify.
	Verify(string) error
}

// writeError responds with a Problem JSON. If err is of type *ServerError,
// its Problem field will be used, otherwise the error will be an
// InternalServerError with Detail taken from the error text.
func writeError(w http.ResponseWriter, err error) {
	serr, ok := err.(*ServerError)
	if !ok {
		err = serverErrorf(http.StatusInternalServerError, ServerInternal, "%v", err)
		serr = err.(*ServerError)
	}

	w.Header().Set(contentTypeHeader, ProblemJSON)
	w.WriteHeader(serr.StatusCode)
	if err := encodeBody(w, ProblemJSON, serr.Problem); err != nil {
		log.Printf("failed to encode problem: %v", err)
	}
}

// writeResponse encodes and writes resp to w, and takes metadata from hresp.
func writeResponse(w http.ResponseWriter, r *http.Request, resp interface{}, hresp *HTTPResponse, ns NonceSource) {
	if hresp.Header != nil {
		// Set response headers.
		for k, vs := range hresp.Header {
			w.Header()[k] = vs
		}
	}

	switch r.Method {
	case "HEAD", "POST":
		// Return a fresh nonce.
		nonce, err := ns.Nonce()
		if err != nil {
			writeError(w, err)
			return
		}
		w.Header().Set(ReplayNonce, nonce)
	}

	if resp == nil {
		// No response body.
		if hresp.StatusCode != 0 {
			w.WriteHeader(hresp.StatusCode)
		}
		return
	}

	// Write response body.
	accept := r.Header.Get(acceptHeader)
	w.Header().Set(contentTypeHeader, accept)
	if hresp.StatusCode != 0 {
		w.WriteHeader(hresp.StatusCode)
	}
	if err := encodeBody(w, accept, resp); err != nil {
		if hresp.StatusCode == 0 {
			writeError(w, err)
			return
		}

		// Returning error would have caused WriteHeader again,
		// causing an error.
		log.Printf("encodeBody failed for %q: %v", r.URL.String(), err)
	}
}

// encodeBody encodes an HTTP body as specified by the contentType.
func encodeBody(w io.Writer, contentType string, in interface{}) error {
	switch contentType {
	case JSON, ProblemJSON:
		return json.NewEncoder(w).Encode(in)

	case PKIXCert:
		bsin, ok := in.([]byte)
		if !ok {
			return fmt.Errorf("expected input to be a []byte, got %T", in)
		}
		_, err := w.Write(bsin)
		return err

	default:
		return fmt.Errorf("unhandled content type: %q", contentType)
	}
}

// readRequest verifies the signature in the JWS body. The nonce is verified
// against ns. If successful, the function returns the key used to sign the body.
func readRequest(out interface{}, r *http.Request, ns NonceSource) (crypto.PublicKey, error) {
	signed := &JSONWebSignature{}
	if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, int64(requestBodyLimit))).Decode(signed); err != nil {
		return nil, serverErrorf(http.StatusBadRequest, Malformed, "%v", err)
	}
	if len(signed.Signatures) != 1 {
		return nil, serverErrorf(http.StatusBadRequest, Malformed, "expected exactly one signature")
	}
	var bs []byte
	bs, err := signed.Verify(signed.Signatures[0].Header.JSONWebKey)
	if err != nil {
		return nil, serverErrorf(http.StatusForbidden, Unauthorized, "%v", err)
	}
	sig := signed.Signatures[0].Header
	if err := ns.Verify(sig.Nonce); err != nil {
		return nil, serverErrorf(http.StatusForbidden, Unauthorized, "%v", err)
	}

	if err := decodeBody(out, r.Header.Get(contentTypeHeader), bytes.NewReader(bs)); err != nil {
		return nil, err
	}
	return sig.JSONWebKey.Key, nil
}
