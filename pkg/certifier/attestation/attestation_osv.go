//
// Copyright 2022 The GUAC Authors.
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

package attestation_osv

import (
	"time"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

const (
	PredicateSCAI = "https://in-toto.io/attestation/vuln/v0.1"
)

// StatementHeader defines the common fields for all statements
type StatementHeader struct {
	Type          string           `json:"_type"`
	PredicateType string           `json:"predicateType"`
	Subject       []intoto.Subject `json:"subject"`
}

type AssertionStatement struct {
	StatementHeader
	// Predicate contains type specific metadata.
	Predicate VulnerabilityPredicate `json:"predicate"`
}

type metadata struct {
	ScannedOn *time.Time `json:"scannedOn,omitempty"`
}

type Result struct {
	VulnerabilityId string   `json:"vulnerability_id,omitempty"`
	Aliases         []string `json:"aliases,omitempty"`
}

type db struct {
	Uri     string `json:"uri,omitempty"`
	Version string `json:"version,omitempty"`
}

type Scanner struct {
	Uri      string   `json:"uri,omitempty"`
	Version  string   `json:"version,omitempty"`
	Database db       `json:"db,omitempty"`
	Result   []Result `json:"result,omitempty"`
}

type Invocation struct {
	Parameters []string `json:"parameters,omitempty"`
	Uri        string   `json:"uri,omitempty"`
	EventID    string   `json:"event_id,omitempty"`
	ProducerID string   `json:"producer_id,omitempty"`
}

type VulnerabilityPredicate struct {
	Invocation Invocation `json:"invocation,omitempty"`
	Scanner    Scanner    `json:"scanner,omitempty"`
	Metadata   metadata   `json:"metadata,omitempty"`
}
