package buildutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Credentials authenticate a registry push. They never reach a log: String redacts.
type Credentials struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	IdentityToken string `json:"identityToken"`
}

// String redacts the secrets (also used by %v and %+v).
func (Credentials) String() string { return "Credentials{redacted}" }

// GoString redacts for %#v.
func (Credentials) GoString() string { return "Credentials{redacted}" }

// ParseCredentials decodes the credentials file: a JSON object with username and password
// and/or identityToken. Unknown fields are rejected so a typo cannot silently drop a secret.
func ParseCredentials(b []byte) (Credentials, error) {
	var c Credentials
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		// err can quote file content; report only that it is malformed
		return Credentials{}, errors.New("credentials file is not valid JSON with username, password, identityToken")
	}
	if c.IdentityToken == "" && (c.Username == "" || c.Password == "") {
		return Credentials{}, fmt.Errorf("credentials file needs identityToken, or username and password")
	}
	return c, nil
}
