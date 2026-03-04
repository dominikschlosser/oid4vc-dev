// Copyright 2026 Dominik Schlosser
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

package wallet

import (
	"testing"

	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
)

func TestEvaluateDCQL_MatchesSDJWTByVCT(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
					map[string]any{"path": []any{"family_name"}},
				},
			},
		},
	}

	matches := w.EvaluateDCQL(query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	m := matches[0]
	if m.QueryID != "pid" {
		t.Errorf("expected query ID 'pid', got %s", m.QueryID)
	}
	if m.Format != "dc+sd-jwt" {
		t.Errorf("expected format dc+sd-jwt, got %s", m.Format)
	}
	if m.VCT != mock.DefaultPIDVCT {
		t.Errorf("expected VCT urn:eudi:pid:1, got %s", m.VCT)
	}
	if len(m.SelectedKeys) != 2 {
		t.Errorf("expected 2 selected keys, got %d: %v", len(m.SelectedKeys), m.SelectedKeys)
	}
}

func TestEvaluateDCQL_MatchesMDocByDocType(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid_mdoc",
				"format": "mso_mdoc",
				"meta": map[string]any{
					"doctype_value": "eu.europa.ec.eudi.pid.1",
				},
				"claims": []any{
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "given_name"}},
				},
			},
		},
	}

	matches := w.EvaluateDCQL(query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	m := matches[0]
	if m.QueryID != "pid_mdoc" {
		t.Errorf("expected query ID 'pid_mdoc', got %s", m.QueryID)
	}
	if m.Format != "mso_mdoc" {
		t.Errorf("expected format mso_mdoc, got %s", m.Format)
	}
	if m.DocType != "eu.europa.ec.eudi.pid.1" {
		t.Errorf("expected DocType eu.europa.ec.eudi.pid.1, got %s", m.DocType)
	}
}

func TestEvaluateDCQL_NoMatchWrongVCT(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "other",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{"urn:eudi:mdl:1"},
				},
			},
		},
	}

	matches := w.EvaluateDCQL(query)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for wrong VCT, got %d", len(matches))
	}
}

func TestEvaluateDCQL_NoMatchWrongFormat(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "wrong",
				"format": "jwt_vc",
			},
		},
	}

	matches := w.EvaluateDCQL(query)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for wrong format, got %d", len(matches))
	}
}

func TestEvaluateDCQL_NoClaims_ReturnsAll(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "all",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
			},
		},
	}

	matches := w.EvaluateDCQL(query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	// Should include all claims since none were specifically requested
	if len(matches[0].SelectedKeys) == 0 {
		t.Error("expected all claims to be selected when no claims specified")
	}
}

func TestEvaluateDCQL_ClaimNotFound(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "missing",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"nonexistent_claim"}},
				},
			},
		},
	}

	matches := w.EvaluateDCQL(query)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches when required claim not found, got %d", len(matches))
	}
}

func TestEvaluateDCQL_MultipleCredentialQueries(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid_sdjwt",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
			map[string]any{
				"id":     "pid_mdoc",
				"format": "mso_mdoc",
				"meta": map[string]any{
					"doctype_value": "eu.europa.ec.eudi.pid.1",
				},
				"claims": []any{
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "given_name"}},
				},
			},
		},
	}

	matches := w.EvaluateDCQL(query)
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}

	foundSDJWT := false
	foundMDoc := false
	for _, m := range matches {
		if m.QueryID == "pid_sdjwt" {
			foundSDJWT = true
		}
		if m.QueryID == "pid_mdoc" {
			foundMDoc = true
		}
	}
	if !foundSDJWT {
		t.Error("expected match for pid_sdjwt")
	}
	if !foundMDoc {
		t.Error("expected match for pid_mdoc")
	}
}

func TestEvaluateDCQL_ClaimSets_StringIDs(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid_sd_jwt",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"id": "family", "path": []any{"family_name"}},
					map[string]any{"id": "given", "path": []any{"given_name"}},
					map[string]any{"id": "birth", "path": []any{"birthdate"}},
				},
				"claim_sets": []any{
					[]any{"family", "given", "birth"}, // all three
					[]any{"family", "given"},          // just name
				},
			},
		},
	}

	matches := w.EvaluateDCQL(query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	// First claim_set should be selected (preference order) — all three claims
	if len(matches[0].SelectedKeys) != 3 {
		t.Errorf("expected 3 selected keys (first claim_set), got %d: %v",
			len(matches[0].SelectedKeys), matches[0].SelectedKeys)
	}
}

func TestEvaluateDCQL_ClaimSets_FallbackToSecond(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"id": "family", "path": []any{"family_name"}},
					map[string]any{"id": "given", "path": []any{"given_name"}},
					map[string]any{"id": "email", "path": []any{"email"}}, // not in PID
				},
				"claim_sets": []any{
					[]any{"family", "email"}, // unsatisfiable (no email claim)
					[]any{"family", "given"}, // satisfiable
				},
			},
		},
	}

	matches := w.EvaluateDCQL(query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	// Second claim_set should be selected (first was unsatisfiable)
	if len(matches[0].SelectedKeys) != 2 {
		t.Errorf("expected 2 selected keys (second claim_set), got %d: %v",
			len(matches[0].SelectedKeys), matches[0].SelectedKeys)
	}
}

func TestEvaluateDCQL_ClaimSets_NoneMatchable(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"id": "email", "path": []any{"email"}},
					map[string]any{"id": "phone", "path": []any{"phone_number"}},
				},
				"claim_sets": []any{
					[]any{"email"},
					[]any{"phone"},
				},
			},
		},
	}

	matches := w.EvaluateDCQL(query)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches when no claim_set satisfiable, got %d", len(matches))
	}
}

func TestEvaluateDCQL_ClaimSets_IntegerIndicesRejected(t *testing.T) {
	w := generateTestWalletWithPID(t)

	// Integer indices are not valid per spec — claim_sets must use string IDs
	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
					map[string]any{"path": []any{"family_name"}},
				},
				"claim_sets": []any{
					[]any{float64(0), float64(1)},
				},
			},
		},
	}

	matches := w.EvaluateDCQL(query)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches when claim_sets uses integer indices, got %d", len(matches))
	}
}

func TestEvaluateDCQL_CredentialSets_Required(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid_sdjwt",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
			map[string]any{
				"id":     "pid_mdoc",
				"format": "mso_mdoc",
				"meta": map[string]any{
					"doctype_value": "eu.europa.ec.eudi.pid.1",
				},
				"claims": []any{
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "given_name"}},
				},
			},
		},
		"credential_sets": []any{
			map[string]any{
				"required": true,
				"options": []any{
					[]any{"pid_sdjwt"},
					[]any{"pid_mdoc"},
				},
			},
		},
	}

	matches := w.EvaluateDCQL(query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match (first option), got %d", len(matches))
	}
	if matches[0].QueryID != "pid_sdjwt" {
		t.Errorf("expected first option pid_sdjwt, got %s", matches[0].QueryID)
	}
}

func TestEvaluateDCQL_CredentialSets_RequiredUnsatisfiable(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "mdl",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{"urn:eudi:mdl:1"}, // not available
				},
			},
		},
		"credential_sets": []any{
			map[string]any{
				"required": true,
				"options": []any{
					[]any{"mdl"},
				},
			},
		},
	}

	matches := w.EvaluateDCQL(query)
	if matches != nil {
		t.Errorf("expected nil for unsatisfiable required credential_set, got %d matches", len(matches))
	}
}

func TestEvaluateDCQL_PartialClaimMatch_Rejected(t *testing.T) {
	w := generateTestWalletWithPID(t)

	// Request given_name (exists in SD-JWT) and a nonexistent claim.
	// The credential should NOT match because the missing claim is required by default.
	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
					map[string]any{"path": []any{"nonexistent_claim"}},
				},
			},
		},
	}

	matches := w.EvaluateDCQL(query)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for partial claim match, got %d", len(matches))
	}
}

func TestEvaluateDCQL_OptionalClaimMissing_Accepted(t *testing.T) {
	w := generateTestWalletWithPID(t)

	// Request given_name (exists) and an optional nonexistent claim.
	// The credential should match because the missing claim is optional.
	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
					map[string]any{"path": []any{"nonexistent_claim"}, "required": false},
				},
			},
		},
	}

	matches := w.EvaluateDCQL(query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match with optional claim missing, got %d", len(matches))
	}
	if len(matches[0].SelectedKeys) != 1 {
		t.Errorf("expected 1 selected key (only given_name), got %d: %v",
			len(matches[0].SelectedKeys), matches[0].SelectedKeys)
	}
}

func TestMatchesFormat(t *testing.T) {
	tests := []struct {
		name   string
		format string
		query  string
		want   bool
	}{
		{"exact match", "dc+sd-jwt", "dc+sd-jwt", true},
		{"mismatch", "dc+sd-jwt", "mso_mdoc", false},
		{"empty query", "dc+sd-jwt", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := StoredCredential{Format: tt.format}
			got := matchesFormat(cred, tt.query)
			if got != tt.want {
				t.Errorf("matchesFormat(%s, %s) = %v, want %v", tt.format, tt.query, got, tt.want)
			}
		})
	}
}

func TestFilterClaims(t *testing.T) {
	claims := map[string]any{
		"given_name":  "Erika",
		"family_name": "Mustermann",
		"birth_date":  "1984-08-12",
	}

	filtered := filterClaims(claims, []string{"given_name", "birth_date"})
	if len(filtered) != 2 {
		t.Fatalf("expected 2 filtered claims, got %d", len(filtered))
	}
	if filtered["given_name"] != "Erika" {
		t.Errorf("expected given_name Erika, got %v", filtered["given_name"])
	}
	if _, ok := filtered["family_name"]; ok {
		t.Error("family_name should not be in filtered claims")
	}
}
