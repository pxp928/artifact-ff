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

package parser

import (
	"fmt"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
)

const (
	algorithmSHA256 string = "sha256"
)

type GraphBuilder interface {
	CreateAssemblerInput([]assembler.IdentityNode) assembler.AssemblerInput
	GetIdentities() []assembler.IdentityNode
}

type docTreeBuilder struct {
	identities    []assembler.IdentityNode
	graphBuilders []GraphBuilder
}

func newDocTreeBuilder() *docTreeBuilder {
	return &docTreeBuilder{
		identities:    []assembler.IdentityNode{},
		graphBuilders: []GraphBuilder{},
	}
}

// ParseDocumentTree takes the DocumentTree and create graph inputs (nodes and edges) per document node
func ParseDocumentTree(docTree processor.DocumentTree) ([]assembler.AssemblerInput, error) {

	assemblerinputs := []assembler.AssemblerInput{}
	docTreeBuilder := newDocTreeBuilder()
	err := docTreeBuilder.parse(docTree)
	if err != nil {
		return nil, err
	}
	for _, builder := range docTreeBuilder.graphBuilders {
		assemblerinput := builder.CreateAssemblerInput(docTreeBuilder.identities)
		assemblerinputs = append(assemblerinputs, assemblerinput)
	}

	return assemblerinputs, nil
}

func (t *docTreeBuilder) parse(root processor.DocumentTree) error {
	builder, err := parseHelper(root.Document)
	if err != nil {
		return err
	}

	t.graphBuilders = append(t.graphBuilders, builder)
	t.identities = append(t.identities, builder.GetIdentities()...)

	if len(root.Children) == 0 {
		return nil
	}

	for _, c := range root.Children {
		err := t.parse(c)
		if err != nil {
			return err
		}
	}
	return nil
}

func parseHelper(doc *processor.Document) (GraphBuilder, error) {
	switch doc.Type {
	case processor.DocumentDSSE:
		return parseDsse(doc)
	case processor.DocumentITE6SLSA:
		return parseITE6Slsa(doc)
	}
	return nil, fmt.Errorf("no parser found for document type: %v", doc.Type)
}
