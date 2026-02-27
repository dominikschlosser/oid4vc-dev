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

package cmd

import (
	"github.com/spf13/cobra"
)

// openidCmd is a hidden backward-compatible alias for "decode".
var openidCmd = &cobra.Command{
	Use:    "openid [input]",
	Short:  "Alias for decode (deprecated)",
	Hidden: true,
	Args:   cobra.MaximumNArgs(1),
	RunE:   runDecode,
}

func init() {
	openidCmd.Flags().StringVar(&decodeQRSource, "qr", "", "scan QR code from image file")
	openidCmd.Flags().BoolVar(&decodeQRScreen, "screen", false, "scan QR code from screen capture")
	openidCmd.Flags().StringVarP(&decodeFormat, "format", "f", "", "pin format: sdjwt, jwt, mdoc, vci, vp")
	rootCmd.AddCommand(openidCmd)
}
