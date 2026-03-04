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
	"log"
	"sort"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/mdoc"
	"github.com/dominikschlosser/oid4vc-dev/internal/sdjwt"
	"github.com/dominikschlosser/oid4vc-dev/internal/trustlist"
	"github.com/dominikschlosser/oid4vc-dev/internal/validate"
)

// EvaluateDCQL matches stored credentials against a DCQL query (OID4VP 1.0 Section 6).
// It returns matched credentials grouped by query credential ID.
func (w *Wallet) EvaluateDCQL(query map[string]any) []CredentialMatch {
	credentials := w.GetCredentials()
	credQueries, _ := query["credentials"].([]any)

	log.Printf("[DCQL] Evaluating query: %d credential queries against %d stored credentials", len(credQueries), len(credentials))

	var matches []CredentialMatch

	for _, cq := range credQueries {
		cqMap, ok := cq.(map[string]any)
		if !ok {
			continue
		}

		queryID, _ := cqMap["id"].(string)
		queryFormat, _ := cqMap["format"].(string)

		for _, cred := range credentials {
			typeLabel := cred.VCT
			if typeLabel == "" {
				typeLabel = cred.DocType
			}

			if !matchesFormat(cred, queryFormat) {
				log.Printf("[DCQL]   query=%s: credential %s (%s) skipped: format mismatch (want %s, have %s)", queryID, typeLabel, cred.Format, queryFormat, cred.Format)
				continue
			}
			if !matchesMeta(cred, cqMap) {
				log.Printf("[DCQL]   query=%s: credential %s (%s) skipped: meta mismatch", queryID, typeLabel, cred.Format)
				continue
			}

			selectedKeys := selectClaims(cred, cqMap)
			if selectedKeys == nil {
				log.Printf("[DCQL]   query=%s: credential %s (%s) skipped: required claims not found", queryID, typeLabel, cred.Format)
				continue
			}

			if taList, ok := cqMap["trusted_authorities"].([]any); ok && len(taList) > 0 {
				if !checkTrustedAuthorities(cred, taList) {
					log.Printf("[DCQL]   query=%s: credential %s (%s) skipped: not trusted by any trusted_authority", queryID, typeLabel, cred.Format)
					continue
				}
			}

			log.Printf("[DCQL]   query=%s: credential %s (%s) matched, selected claims: %v", queryID, typeLabel, cred.Format, selectedKeys)
			matches = append(matches, CredentialMatch{
				QueryID:      queryID,
				CredentialID: cred.ID,
				Format:       cred.Format,
				VCT:          cred.VCT,
				DocType:      cred.DocType,
				Claims:       filterClaims(cred.Claims, selectedKeys),
				SelectedKeys: selectedKeys,
			})
		}
	}

	// Sort matches so preferred format appears first per query ID
	if w.PreferredFormat != "" {
		sort.SliceStable(matches, func(i, j int) bool {
			if matches[i].QueryID == matches[j].QueryID {
				return matches[i].Format == w.PreferredFormat
			}
			return false
		})
	}

	// Apply credential_sets constraints
	if credSets, ok := query["credential_sets"].([]any); ok {
		log.Printf("[DCQL] Applying credential_sets constraints: %d sets, %d matches before", len(credSets), len(matches))
		matches = applyCredentialSets(matches, credSets, w.PreferredFormat)
		if matches == nil {
			log.Printf("[DCQL] credential_sets: unsatisfiable required set")
		} else {
			log.Printf("[DCQL] credential_sets: %d matches after filtering", len(matches))
		}
	}

	log.Printf("[DCQL] Result: %d matches", len(matches))
	return matches
}

// matchesFormat checks if a credential matches the requested format.
func matchesFormat(cred StoredCredential, queryFormat string) bool {
	if queryFormat == "" {
		return true
	}
	return cred.Format == queryFormat
}

// matchesMeta checks format-specific metadata (vct_values, doctype_value).
func matchesMeta(cred StoredCredential, cqMap map[string]any) bool {
	meta, ok := cqMap["meta"].(map[string]any)
	if !ok {
		return true
	}

	// SD-JWT: check vct_values
	if vctValues, ok := meta["vct_values"].([]any); ok {
		if cred.VCT == "" {
			return false
		}
		found := false
		for _, v := range vctValues {
			if s, ok := v.(string); ok && s == cred.VCT {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// mDoc: check doctype_value
	if docType, ok := meta["doctype_value"].(string); ok {
		if cred.DocType != docType {
			return false
		}
	}

	return true
}

// selectClaims determines which claims to disclose based on the query.
// Returns claim keys to disclose, or nil if the credential can't satisfy the query.
func selectClaims(cred StoredCredential, cqMap map[string]any) []string {
	claimsQuery, ok := cqMap["claims"].([]any)
	if !ok || len(claimsQuery) == 0 {
		// No specific claims requested, include all
		all := make([]string, 0, len(cred.Claims))
		for k := range cred.Claims {
			all = append(all, k)
		}
		return all
	}

	// Check claim_sets first (preference ordering)
	if claimSets, ok := cqMap["claim_sets"].([]any); ok && len(claimSets) > 0 {
		return selectFromClaimSets(cred, claimsQuery, claimSets)
	}

	// No claim_sets: include all requested claims that exist
	return selectAllRequestedClaims(cred, claimsQuery)
}

// selectFromClaimSets picks the first satisfiable claim_set (preference order).
// claim_sets entries reference claims by their "id" property (string).
func selectFromClaimSets(cred StoredCredential, claimsQuery []any, claimSets []any) []string {
	// Build index: claim id → claim path
	claimByID := buildClaimByID(claimsQuery)

	for _, cs := range claimSets {
		csArr, ok := cs.([]any)
		if !ok {
			continue
		}

		var selected []string
		satisfiable := true

		for _, ref := range csArr {
			id, ok := ref.(string)
			if !ok {
				satisfiable = false
				break
			}

			path := claimByID[id]
			if path == nil {
				satisfiable = false
				break
			}

			key := claimKeyFromPath(cred, path)
			if key == "" {
				satisfiable = false
				break
			}
			selected = append(selected, key)
		}

		if satisfiable && len(selected) > 0 {
			return selected
		}
	}

	return nil
}

// buildClaimByID builds a map of claim id → path from claims query entries.
func buildClaimByID(claimsQuery []any) map[string][]any {
	byID := make(map[string][]any)
	for _, cq := range claimsQuery {
		cqMap, ok := cq.(map[string]any)
		if !ok {
			continue
		}
		id, _ := cqMap["id"].(string)
		if id == "" {
			continue
		}
		path, ok := cqMap["path"].([]any)
		if !ok {
			continue
		}
		byID[id] = path
	}
	return byID
}

// selectAllRequestedClaims returns all requested claims that exist in the credential.
// Per DCQL (OID4VP 1.0 Section 6), claims without claim_sets are required by default
// unless the individual claim entry has "required": false.
// Returns nil if any required claim is missing.
func selectAllRequestedClaims(cred StoredCredential, claimsQuery []any) []string {
	var selected []string
	for _, cq := range claimsQuery {
		cqMap, ok := cq.(map[string]any)
		if !ok {
			continue
		}
		path, ok := cqMap["path"].([]any)
		if !ok {
			continue
		}

		// Per DCQL spec: claims are required by default.
		required := true
		if r, ok := cqMap["required"].(bool); ok {
			required = r
		}

		key := claimKeyFromPath(cred, path)
		if key != "" {
			selected = append(selected, key)
		} else if required {
			return nil
		}
	}
	if len(selected) == 0 {
		return nil
	}
	return selected
}

// claimKeyFromPath resolves a DCQL claim path to a credential claim key.
// For SD-JWT: path is like ["given_name"] → key "given_name"
//
//	nested object: ["address", "street_address"] → validates subclaim exists, returns "address"
//	array wildcard: ["nationalities", null] → validates value is array, returns "nationalities"
//	array index:    ["nationalities", 0] → validates array has enough elements, returns "nationalities"
//
// For mDoc: path is like ["eu.europa.ec.eudi.pid.1", "given_name"] → key "eu.europa.ec.eudi.pid.1:given_name"
func claimKeyFromPath(cred StoredCredential, path []any) string {
	if len(path) == 0 {
		return ""
	}

	if cred.Format == "mso_mdoc" && len(path) >= 2 {
		ns, ok1 := path[0].(string)
		elem, ok2 := path[1].(string)
		if ok1 && ok2 {
			key := ns + ":" + elem
			if _, exists := cred.Claims[key]; exists {
				return key
			}
		}
		return ""
	}

	// SD-JWT
	key, ok := path[0].(string)
	if !ok {
		return ""
	}
	val, exists := cred.Claims[key]
	if !exists {
		return ""
	}

	// Single-segment path: just check existence
	if len(path) == 1 {
		return key
	}

	// Multi-segment: validate nested structure
	switch second := path[1].(type) {
	case string:
		// Nested object path like ["address", "street_address"]
		obj, ok := val.(map[string]any)
		if !ok {
			return ""
		}
		if _, exists := obj[second]; !exists {
			return ""
		}
		return key
	case float64:
		// Array index like ["nationalities", 0]
		arr, ok := val.([]any)
		if !ok {
			return ""
		}
		idx := int(second)
		if idx < 0 || idx >= len(arr) {
			return ""
		}
		return key
	case nil:
		// Array wildcard like ["nationalities", null]
		if _, ok := val.([]any); !ok {
			return ""
		}
		return key
	default:
		return ""
	}
}

// filterClaims returns only the claims with the given keys.
func filterClaims(claims map[string]any, selectedKeys []string) map[string]any {
	filtered := make(map[string]any, len(selectedKeys))
	for _, k := range selectedKeys {
		if v, ok := claims[k]; ok {
			filtered[k] = v
		}
	}
	return filtered
}

// applyCredentialSets filters matches to satisfy credential_sets constraints.
// When preferredFormat is set, options containing credentials of that format are tried first.
func applyCredentialSets(matches []CredentialMatch, credSets []any, preferredFormat string) []CredentialMatch {
	// Group matches by query ID
	byQuery := make(map[string][]CredentialMatch)
	for _, m := range matches {
		byQuery[m.QueryID] = append(byQuery[m.QueryID], m)
	}

	// Build a map of query ID → format for preference sorting
	queryFormat := make(map[string]string)
	for qid, ms := range byQuery {
		if len(ms) > 0 {
			queryFormat[qid] = ms[0].Format
		}
	}

	// Track which query IDs are needed
	needed := make(map[string]bool)

	for _, cs := range credSets {
		csMap, ok := cs.(map[string]any)
		if !ok {
			continue
		}

		required := true
		if r, ok := csMap["required"].(bool); ok {
			required = r
		}

		options, ok := csMap["options"].([]any)
		if !ok {
			continue
		}

		// Reorder options to prefer the preferred format
		orderedOptions := options
		if preferredFormat != "" {
			orderedOptions = make([]any, len(options))
			copy(orderedOptions, options)
			sort.SliceStable(orderedOptions, func(i, j int) bool {
				return optionMatchesFormat(orderedOptions[i], queryFormat, preferredFormat) &&
					!optionMatchesFormat(orderedOptions[j], queryFormat, preferredFormat)
			})
		}

		// Try each option (array of credential query IDs)
		satisfied := false
		for _, opt := range orderedOptions {
			optArr, ok := opt.([]any)
			if !ok {
				continue
			}

			allAvailable := true
			for _, qid := range optArr {
				qidStr, ok := qid.(string)
				if !ok {
					allAvailable = false
					break
				}
				if _, has := byQuery[qidStr]; !has {
					allAvailable = false
					break
				}
			}

			if allAvailable {
				for _, qid := range optArr {
					if qidStr, ok := qid.(string); ok {
						needed[qidStr] = true
					}
				}
				satisfied = true
				break
			}
		}

		if required && !satisfied {
			return nil // required credential_set not satisfiable
		}
	}

	// If no credential_sets were defined or all optional, include everything
	if len(needed) == 0 {
		return matches
	}

	// Filter to only needed matches (first match per query ID)
	var result []CredentialMatch
	used := make(map[string]bool)
	for _, m := range matches {
		if needed[m.QueryID] && !used[m.QueryID] {
			result = append(result, m)
			used[m.QueryID] = true
		}
	}
	return result
}

// optionMatchesFormat checks if a credential_sets option contains query IDs
// whose matches are all of the given format.
func optionMatchesFormat(opt any, queryFormat map[string]string, format string) bool {
	optArr, ok := opt.([]any)
	if !ok {
		return false
	}
	for _, qid := range optArr {
		qidStr, ok := qid.(string)
		if !ok {
			return false
		}
		if queryFormat[qidStr] == format {
			return true
		}
	}
	return false
}

// checkTrustedAuthorities validates that the credential's issuer certificate chain
// is trusted by at least one of the given trusted authorities.
// Each entry must have "type" and "value" fields. Only "etsi_tl" type is supported.
func checkTrustedAuthorities(cred StoredCredential, taList []any) bool {
	for _, taRaw := range taList {
		taMap, ok := taRaw.(map[string]any)
		if !ok {
			continue
		}
		taType, _ := taMap["type"].(string)
		taValue, _ := taMap["value"].(string)

		switch taType {
		case "etsi_tl":
			if taValue == "" {
				log.Printf("[DCQL]   trusted_authorities: etsi_tl entry missing value")
				continue
			}
			if checkETSITrustList(cred, taValue) {
				return true
			}
		default:
			log.Printf("[DCQL]   trusted_authorities: unsupported type %q", taType)
		}
	}
	return false
}

// checkETSITrustList fetches an ETSI trust list and validates the credential's
// issuer certificate chain against it.
func checkETSITrustList(cred StoredCredential, trustListURL string) bool {
	tlRaw, err := format.FetchURL(trustListURL)
	if err != nil {
		log.Printf("[DCQL]   trusted_authorities: failed to fetch trust list %s: %v", trustListURL, err)
		return false
	}

	tl, err := trustlist.Parse(tlRaw)
	if err != nil {
		log.Printf("[DCQL]   trusted_authorities: failed to parse trust list: %v", err)
		return false
	}

	tlCerts := trustlist.ExtractPublicKeys(tl)
	if len(tlCerts) == 0 {
		log.Printf("[DCQL]   trusted_authorities: trust list contains no certificates")
		return false
	}

	switch cred.Format {
	case "dc+sd-jwt":
		token, err := sdjwt.Parse(cred.Raw)
		if err != nil {
			log.Printf("[DCQL]   trusted_authorities: failed to parse SD-JWT: %v", err)
			return false
		}
		key, err := validate.ExtractAndValidateX5C(token.Header, tlCerts)
		if err != nil {
			log.Printf("[DCQL]   trusted_authorities: x5c chain validation failed: %v", err)
			return false
		}
		return key != nil

	case "mso_mdoc":
		doc, err := mdoc.Parse(cred.Raw)
		if err != nil {
			log.Printf("[DCQL]   trusted_authorities: failed to parse mDoc: %v", err)
			return false
		}
		key, err := validate.ExtractAndValidateMDOCX5Chain(doc, tlCerts)
		if err != nil {
			log.Printf("[DCQL]   trusted_authorities: x5chain validation failed: %v", err)
			return false
		}
		return key != nil

	default:
		log.Printf("[DCQL]   trusted_authorities: unsupported credential format %q for chain validation", cred.Format)
		return false
	}
}
