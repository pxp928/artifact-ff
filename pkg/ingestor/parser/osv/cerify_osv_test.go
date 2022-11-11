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

package certify_osv

import (
	"context"
	"reflect"
	"testing"

	testdata_ing "github.com/guacsec/guac/internal/testing/ingestor/testdata"
	testdata "github.com/guacsec/guac/internal/testing/processor"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func Test_osvCertificationParser(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name      string
		doc       *processor.Document
		wantNodes []assembler.GuacNode
		wantEdges []assembler.GuacEdge
		wantErr   bool
	}{{
		name: "testing",
		doc: &processor.Document{
			Blob:   testdata.ITE6OSVExmple,
			Type:   processor.DocumentITE6OSV,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		/* wantNodes: []assembler.GuacNode{artNode, attNode},
		wantEdges: []assembler.GuacEdge{
			assembler.IdentityForEdge{
				IdentityNode:    testdata_ing.Ident,
				AttestationNode: attNode,
			},
			assembler.AttestationForEdge{
				AttestationNode: attNode,
				ArtifactNode:    artNode,
			},
		}, */
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewOSVCertificationParser()
			if err := c.Parse(ctx, tt.doc); (err != nil) != tt.wantErr {
				t.Errorf("cerify.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if nodes := c.CreateNodes(ctx); !reflect.DeepEqual(nodes, tt.wantNodes) {
				t.Errorf("cerify.CreateNodes() = %v, want %v", nodes, tt.wantNodes)
			}
			if edges := c.CreateEdges(ctx, []assembler.IdentityNode{testdata_ing.Ident}); !reflect.DeepEqual(edges, tt.wantEdges) {
				t.Errorf("cerify.CreateEdges() = %v, want %v", edges, tt.wantEdges)
			}
		})
	}
}
