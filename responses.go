// Copyright The Linux Foundation and its contributors.
// SPDX-License-Identifier: MIT

// The auth0-cas-service-go service.
package main

// spell-checker:disable
import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// spell-checker:enable

type casValidationResponse struct {
	ServiceResponse casServiceResponse `json:"serviceResponse" xml:"-"`
}

type casServiceResponse struct {
	// I'm not able to get `xmlns:cas` to show up using native namespace in
	// XMLName, so we're using a workaround of setting a XMLNS attribute.
	XMLName xml.Name `json:"-" xml:"cas:serviceResponse"`
	XMLNS   string   `json:"-" xml:"xmlns:cas,attr"`

	AuthenticationSuccess *casAuthenticationSuccess `json:"authenticationSuccess,omitempty" xml:"cas:authenticationSuccess,omitempty"`
	AuthenticationFailure *casAuthenticationFailure `json:"authenticationFailure,omitempty" xml:"cas:authenticationFailure,omitempty"`
}

type casAuthenticationSuccess struct {
	User       string        `json:"user" xml:"cas:user"`
	Attributes casAttributes `json:"attributes" xml:"cas:attributes"`
}

type casAttributes struct {
	// The order of the struct attributes matters. XML is an inherently ordered
	// document, and we are preserving as much as possible the output from
	// our reference implementation. (Including first/full/last for field_* but
	// first/last/full for profile_*).
	// cspell:disable-next-line
	AttributesStyle string   `json:"-" xml:"cas:attraStyle"`
	UID             string   `json:"-" xml:"cas:uid"`
	Email           string   `json:"email" xml:"cas:mail"`
	Created         uint64   `json:"-" xml:"cas:created"`
	Timezone        string   `json:"timezone,omitempty" xml:"cas:timezone,omitempty"`
	Language        string   `json:"-" xml:"cas:language"`
	Groups          []string `json:"groups" xml:"cas:group,omitempty"`
	GivenName       string   `json:"given_name" xml:"cas:field_lf_first_name"`
	FullName        string   `json:"name" xml:"cas:field_lf_full_name"`
	FamilyName      string   `json:"family_name" xml:"cas:field_lf_last_name"`
	GivenNameOld    string   `json:"-" xml:"cas:profile_name_first"`
	FamilyNameOld   string   `json:"-" xml:"cas:profile_name_last"`
	FullNameOld     string   `json:"-" xml:"cas:profile_name_full"`
}

type casAuthenticationFailure struct {
	Code        string `json:"code" xml:"code,attr"`
	Description string `json:"description" xml:",chardata"`
}

var (
	// spell-checker:disable
	// mb4RE matches anything outside the range of mb3 characters (\u0000-\uD7FF and
	// \uE000-\uEEEE) with mb3 emoji excluded (\u203C-\u26ff).
	mb4RE = regexp.MustCompile(`[^\x{0000}-\x{203B}\x{2700}-\x{D7FF}\x{E000}-\x{FFFF}]`)

	// mbIllegalRE and spacesRE are based on Drupal 7 allowed characters for
	// usernames.
	mbIllegalRE = regexp.MustCompile(`[\x{80}-\x{A0}\x{AD}\x{2000}-\x{200F}\x{2028}-\x{202F}\x{205F}-\x{206F}\x{FEFF}\x{FF01}-\x{FF60}\x{FFF9}-\x{FFFD}\x{0}-\x{1F}]`)
	spacesRE    = regexp.MustCompile(`[[:space:]]+`)

	// spell-checker:enable
)

func validationResponse(success *casAuthenticationSuccess, failure *casAuthenticationFailure, useJSON bool) (string, error) {
	if success != nil && failure != nil {
		return "", errors.New("must pass either a success or failure response, not both")
	}
	if success != nil {
		// Normalize attributes for defaults and safety.
		success.Attributes.Normalize()
	}
	response := casValidationResponse{casServiceResponse{
		XMLNS:                 "http://www.yale.edu/tp/cas",
		AuthenticationSuccess: success,
		AuthenticationFailure: failure,
	}}

	var output []byte
	var err error
	switch useJSON {
	case true:
		output, err = json.MarshalIndent(response, "", "  ")
	default:
		output, err = xml.MarshalIndent(response.ServiceResponse, "<repl />", "")
		// Hack to have newlines but no indentation.
		xmlFix := strings.ReplaceAll(string(output), "<repl />", "")
		// Some clients aren't implementing XML correctly.
		xmlFix = strings.ReplaceAll(xmlFix, `"`, "'")
		output = []byte(xmlFix)
	}
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// Normalize processes a passed attributes object and ensure attributes are
// safe for storage in MySQL legacy utf8 (3-byte encoding).
func (attr *casAttributes) Normalize() {
	// Set phpCAS "attributes style" flag to the default if unset.
	if attr.AttributesStyle == "" {
		attr.AttributesStyle = "Jasig"
	}

	// Normalize name(s).
	attr.FullName = mb4Filter(attr.FullName)
	attr.FullNameOld = attr.FullName
	attr.GivenName = mb4Filter(attr.GivenName)
	attr.GivenNameOld = attr.GivenName
	attr.FamilyName = mb4Filter(attr.FamilyName)
	attr.FamilyNameOld = attr.FamilyName
}

// mb4Filter processes a string to remove characters which would require 4-byte
// encoding (incompatible with MySQL utf8 encoding), 3-byte-encoded emojis,
// control characters, and utf8 whitespace. Consecutive whitespace is also
// collapsed to a single space.
func mb4Filter(text string) string {
	// Normalizing UTF8 using NFKC (Compatibility Decomposition, followed by
	// Canonical Composition) will convert some emoji to characters in our target
	// set, removing font and character variants (circled, width,
	// sub/superscript, fractions), while also ensuring we use more compact
	// singletons where possible (instead of composites).
	text = norm.NFKC.String(text)

	// After UTF8 normalization, we strip any remaining characters which have
	// 4-byte encodings, as well as the range of emoji characters in the 3-byte
	// range.
	text = mb4RE.ReplaceAllString(text, ".")

	// Switch control characters and utf8 whitespace to spaces.
	text = mbIllegalRE.ReplaceAllString(text, " ")

	// Collapse consecutive whitespace.
	text = spacesRE.ReplaceAllString(text, " ")

	// Strip leading and trailing whitespace.
	text = strings.TrimSpace(text)

	return text
}
