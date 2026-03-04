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
	"fmt"
	"strings"

	"github.com/dominikschlosser/oid4vc-dev/internal/jsonutil"
	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
)

// ValidateHAIPCompliance checks an authorization request against HAIP 1.0 requirements.
// Returns a list of violation messages. Empty list means compliant.
//
// HAIP 1.0 requires:
//   - response_mode MUST be direct_post.jwt (encrypted responses)
//   - client_id MUST use x509_hash: scheme
//   - Signed Request Objects (JAR) MUST be used
//   - DCQL query MUST be used (not presentation_definition)
//   - Request Object alg MUST be ES256
func ValidateHAIPCompliance(params *AuthorizationRequestParams, reqObj *oid4vc.RequestObjectJWT) []string {
	var violations []string

	// §5.1.2.3: response_mode MUST be direct_post.jwt
	if params.ResponseMode != "direct_post.jwt" {
		violations = append(violations, fmt.Sprintf(
			"HAIP: response_mode MUST be 'direct_post.jwt', got %q", params.ResponseMode))
	}

	// §5.2.3: client_id MUST use x509_hash: prefix
	if !strings.HasPrefix(params.ClientID, "x509_hash:") {
		violations = append(violations, fmt.Sprintf(
			"HAIP: client_id MUST use 'x509_hash:' scheme, got %q", params.ClientID))
	}

	// §5.1.2.2: Signed Request Objects (JAR) MUST be used
	if reqObj == nil || reqObj.Header == nil {
		violations = append(violations, "HAIP: signed Request Object (JAR) MUST be used")
	}

	// §5.2.4: DCQL query MUST be used
	if params.DCQLQuery == nil {
		violations = append(violations, "HAIP: DCQL query MUST be used (not presentation_definition)")
	}

	// §7: ES256 MUST be supported; request object alg MUST be ES256
	if reqObj != nil && reqObj.Header != nil {
		alg := jsonutil.GetString(reqObj.Header, "alg")
		if alg != "" && alg != "ES256" {
			violations = append(violations, fmt.Sprintf(
				"HAIP: Request Object algorithm MUST be ES256, got %q", alg))
		}
	}

	return violations
}
