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

// Package config provides shared default constants used across the CLI and internal packages.
package config

import (
	"os"
	"path/filepath"
	"time"
)

const (
	DefaultWalletPort = 8085

	DefaultServePort = 8080

	DefaultProxyPort = 9090

	DefaultProxyDashboardPort = 9091

	ConsentTimeout = 5 * time.Minute

	// The CLI uses the same timeout as the authorization flow so it stops polling when
	// the wallet stops waiting for sign-in.
	AuthorizationCallbackWait = 5 * time.Minute

	// Sign-in and consent can take longer than ordinary HTTP requests. This timeout
	// covers server response writes, remote CLI requests and consent approval waits.
	SlowRequestTimeout = 2 * time.Minute
)

// ClientHeader names the client behind an API call and its release, as
// "<name>/<version>". OwnerHeader names the browser a client submits on behalf
// of. Both live here because the wallet reads them and the CLI sends them.
const (
	ClientHeader = "X-Eudi-Client"
	OwnerHeader  = "X-Eudi-Owner"
)

// BaseDir returns the tool's state directory. Resolution order: the
// EUDI_DEV_HOME environment variable, the legacy OID4VC_DEV_HOME variable,
// an existing ~/.eudi-dev directory, an existing legacy ~/.oid4vc-dev
// directory, and ~/.eudi-dev otherwise.
func BaseDir() string {
	if custom := os.Getenv("EUDI_DEV_HOME"); custom != "" {
		return custom
	}
	if custom := os.Getenv("OID4VC_DEV_HOME"); custom != "" {
		return custom
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	newDir := filepath.Join(home, ".eudi-dev")
	legacyDir := filepath.Join(home, ".oid4vc-dev")
	if _, err := os.Stat(newDir); err == nil {
		return newDir
	}
	if _, err := os.Stat(legacyDir); err == nil {
		return legacyDir
	}
	return newDir
}
