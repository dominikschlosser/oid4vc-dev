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

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/oid4vc-dev/internal/config"
	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
)

func walletGeneratePIDCmd() *cobra.Command {
	var (
		claimsFlag string
		keyPath    string
		vctFlag    string
		statusList bool
		baseURL    string
		docker     bool
	)

	cmd := &cobra.Command{
		Use:   "generate-pid",
		Short: "Generate default EUDI PID credentials (SD-JWT + mDoc)",
		Long:  "Generate EUDI PID credentials with default claims. If PID credentials already exist, they are replaced. Use --claims to override specific claim values.",
		RunE: func(cmd *cobra.Command, args []string) error {
			w, store, err := loadWallet()
			if err != nil {
				return err
			}

			if keyPath != "" {
				issuerKey, err := loadWalletECKey(keyPath, "issuer")
				if err != nil {
					return err
				}
				w.IssuerKey = issuerKey
			}

			if statusList {
				if baseURL == "" {
					if docker {
						baseURL = fmt.Sprintf("http://host.docker.internal:%d", config.DefaultWalletPort)
					} else {
						baseURL = fmt.Sprintf("http://localhost:%d", config.DefaultWalletPort)
					}
				}
				w.BaseURL = baseURL
			}

			overrides, err := parseClaimsOverrides(claimsFlag)
			if err != nil {
				return err
			}

			if err := w.GenerateDefaultCredentials(overrides, vctFlag); err != nil {
				return fmt.Errorf("generating PID credentials: %w", err)
			}

			if err := store.Save(w); err != nil {
				return fmt.Errorf("saving wallet: %w", err)
			}

			fmt.Println("Generated default EUDI PID credentials (SD-JWT + mDoc)")
			return nil
		},
	}

	cmd.Flags().StringVar(&claimsFlag, "claims", "", "Claim overrides as JSON (e.g. '{\"given_name\":\"Max\"}')")
	cmd.Flags().StringVar(&keyPath, "key", "", "Path to PEM-encoded EC private key for signing (default: auto-generated)")
	cmd.Flags().StringVar(&vctFlag, "vct", mock.DefaultPIDVCT, "Verifiable Credential Type for SD-JWT PID")
	cmd.Flags().BoolVar(&statusList, "status-list", false, "Embed status list references in generated credentials")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Base URL for status list endpoint (default: http://localhost:8085)")
	cmd.Flags().BoolVar(&docker, "docker", false, "Use host.docker.internal instead of localhost for --base-url")
	return cmd
}
