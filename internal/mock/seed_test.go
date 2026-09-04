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

package mock

import "testing"

// The same seed and label always give the same key, different labels give
// independent ones, and an empty seed gives fresh ones.
func TestSeed_DerivesTheSameKeyForTheSameLabel(t *testing.T) {
	seed := Seed("bench")
	first, err := seed.Key("holder")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := Seed("bench").Key("holder")
	if !first.Equal(again) {
		t.Fatal("the same seed and label gave different keys")
	}
	other, _ := seed.Key("issuer")
	if first.Equal(other) {
		t.Fatal("two labels gave the same key")
	}
	otherSeed, _ := Seed("bench-2").Key("holder")
	if first.Equal(otherSeed) {
		t.Fatal("two seeds gave the same key")
	}

	random, _ := Seed("").Key("holder")
	randomAgain, _ := Seed("").Key("holder")
	if random.Equal(randomAgain) {
		t.Fatal("no seed gave the same key twice")
	}
}
