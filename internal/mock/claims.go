// Copyright 2025 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package mock generates test credentials (SD-JWT and mDOC) with default EUDI PID claims.
package mock

// DefaultPIDVCT is the default Verifiable Credential Type for German EUDI PIDs.
const DefaultPIDVCT = "urn:eudi:pid:de:1"

// DefaultClaims returns a minimal set of PID-like claims.
var DefaultClaims = map[string]any{
	"given_name":  "ERIKA",
	"family_name": "MUSTERMANN",
	"birthdate":   "1984-08-12",
}

// SDJWTPIDClaims returns claims following the EUDI PID Rulebook for SD-JWT format.
// address is a nested object with individually disclosable subclaims.
// nationalities is an array with individually disclosable elements.
// document_number and administrative_number are omitted (not present in German PIDs).
var SDJWTPIDClaims = map[string]any{
	"family_name":       "MUSTERMANN",
	"given_name":        "ERIKA",
	"birthdate":         "1984-08-12",
	"age_over_18":       true,
	"age_in_years":      41,
	"age_birth_year":    1984,
	"family_name_birth": "GABLER",
	"given_name_birth":  "ERIKA",
	"birth_place":       "BERLIN",
	"birth_country":     "DE",
	"birth_state":       "BE",
	"birth_city":        "BERLIN",
	"address": map[string]any{
		"street_address": "HEIDESTRAẞE 17",
		"locality":       "KÖLN",
		"postal_code":    "51147",
		"country":        "DE",
		"region":         "NW",
	},
	"gender":        1,
	"nationalities": []any{"DE"},
	"issuance_date":       "2024-01-15",
	"expiry_date":         "2029-01-15",
	"issuing_authority":   "DE",
	"issuing_country":     "DE",
	"issuing_jurisdiction": "DE-NW",
}

// MDOCPIDClaims returns claims following the EUDI PID Rulebook for mDoc format.
// Uses flat data elements per ISO 18013-5 / eu.europa.ec.eudi.pid.1 namespace.
// document_number and administrative_number are omitted (not present in German PIDs).
var MDOCPIDClaims = map[string]any{
	"family_name":         "MUSTERMANN",
	"given_name":          "ERIKA",
	"birth_date":          "1984-08-12",
	"age_over_18":         true,
	"age_in_years":        41,
	"age_birth_year":      1984,
	"family_name_birth":   "GABLER",
	"given_name_birth":    "ERIKA",
	"birth_place":         "BERLIN",
	"birth_country":       "DE",
	"birth_state":         "BE",
	"birth_city":          "BERLIN",
	"resident_address":    "HEIDESTRAẞE 17, 51147 KÖLN",
	"resident_country":    "DE",
	"resident_state":      "NW",
	"resident_city":       "KÖLN",
	"resident_postal_code": "51147",
	"resident_street":     "HEIDESTRAẞE 17",
	"gender":              1,
	"nationality":         "DE",
	"issuance_date":       "2024-01-15",
	"expiry_date":         "2029-01-15",
	"issuing_authority":   "DE",
	"issuing_country":     "DE",
	"issuing_jurisdiction": "DE-NW",
}

// PIDClaims is an alias for SDJWTPIDClaims for backward compatibility.
// Deprecated: Use SDJWTPIDClaims or MDOCPIDClaims depending on the credential format.
var PIDClaims = SDJWTPIDClaims
