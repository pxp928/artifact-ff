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
	PredicateSCAI = "http://in-toto.io/attestation/scai/attribute-assertion/v0.1"
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
	Predicate AssertionPredicate `json:"predicate"`
}

type Attribute struct {
	Attribute string   `json:"attribute"`
	Evidence  Evidence `json:"evidence"`
}

// Certifier identifies the entity
type Evidence struct {
	Scanner Scanner    `json:"scanner"`
	Results []Result   `json:"results"`
	Date    *time.Time `json:"date"`
}

type Result struct {
	OSVID string `json:"OSVID"`
}

type Scanner struct {
	Type string `json:"type"`
	Id   string `json:"id"`
}

type Producer struct {
	Type string `json:"type"`
	Id   string `json:"id"`
}

type AssertionPredicate struct {
	Producer   Producer    `json:"producer"`
	Attributes []Attribute `json:"attributes"`
}
