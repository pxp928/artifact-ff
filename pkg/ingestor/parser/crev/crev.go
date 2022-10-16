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

package crev

import (
	"time"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

const (
	// PredicateCrev represents a CREV provenance for an artifact.
	PredicateCrev = "https://crev.dev/in-toto-scheme/v-1"
)

// StatementHeader defines the common fields for all statements
type StatementHeader struct {
	Type          string           `json:"_type"`
	PredicateType string           `json:"predicateType"`
	Subject       []intoto.Subject `json:"subject"`
}

type CrevStatement struct {
	StatementHeader
	// Predicate contains type speficic metadata.
	Predicate CrevPredicate `json:"predicate"`
}

// Reviewer identifies the entity
type Reviewer struct {
	IDType string `json:"id-type"`
	ID     string `json:"id"`
	URL    string `json:"url"`
}

// CrevPredicate is the provenance predicate definition.
type CrevPredicate struct {
	Reviewer Reviewer `json:"reviewer-id"`

	Date          *time.Time `json:"date,omitempty"`
	Thoroughness  string     `json:"thoroughness,omitempty"`
	Understanding string     `json:"understanding,omitempty"`
	Rating        string     `json:"rating,omitempty"`
	Comment       string     `json:"comment,omitempty"`
}
