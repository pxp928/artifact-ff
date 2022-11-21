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
	"testing"

	"github.com/guacsec/guac/internal/testing/ingestor/testdata"
	processor_data "github.com/guacsec/guac/internal/testing/processor"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

var (
	// osvCertifier testdata

	log4jPack = assembler.PackageNode{
		Name:    "",
		Digest:  nil,
		Version: "",
		Purl:    "pkg:maven/org.apache.logging.log4j/log4j-core@2.8.1",
		Tags:    nil,
		CPEs:    nil,
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "",
				Source:    "",
			},
		),
	}

	vulAttest = assembler.AttestationNode{
		FilePath:        "TestSource",
		Digest:          "sha256:8546e78671836aab74c2dd554b4939547ae950ff3ecc89fcbedf69a7b11bbe0c",
		AttestationType: "CERTIFY_OSV",
		Payload: map[string]interface{}{
			"invocation_parameters":   []string{""},
			"invocation_eventID":      "",
			"invocation_uri":          "guac",
			"invocation_producerID":   "guac",
			"scanner_uri":             "osv.dev",
			"scanner_version":         "0.0.14",
			"scanner_db_uri":          "",
			"scanner_db_version":      "",
			"metadata_scannedOn":      "2022-11-21 17:45:50.52 +0000 UTC",
			"result_vulnerabilityID0": "GHSA-7rjr-3q55-vv33",
			"result_alias0":           []string{""},
			"result_vulnerabilityID1": "GHSA-8489-44mv-ggj8",
			"result_alias1":           []string{""},
			"result_vulnerabilityID2": "GHSA-fxph-q3j8-mv87",
			"result_alias2":           []string{""},
			"result_vulnerabilityID3": "GHSA-jfh8-c2jp-5v3q",
			"result_alias3":           []string{""},
			"result_vulnerabilityID4": "GHSA-p6xc-xr62-6r2g",
			"result_alias4":           []string{""},
			"result_vulnerabilityID5": "GHSA-vwqq-5vrc-xw9h",
			"result_alias5":           []string{""},
		},
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}

	vulNode1 = assembler.VulnerabilityNode{
		ID: "GHSA-7rjr-3q55-vv33",
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}
	vulNode2 = assembler.VulnerabilityNode{
		ID: "GHSA-8489-44mv-ggj8",
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}
	vulNode3 = assembler.VulnerabilityNode{
		ID: "GHSA-fxph-q3j8-mv87",
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}
	vulNode4 = assembler.VulnerabilityNode{
		ID: "GHSA-jfh8-c2jp-5v3q",
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}
	vulNode5 = assembler.VulnerabilityNode{
		ID: "GHSA-p6xc-xr62-6r2g",
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}
	vulNode6 = assembler.VulnerabilityNode{
		ID: "GHSA-vwqq-5vrc-xw9h",
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}

	osvCertifierEdges = []assembler.GuacEdge{
		assembler.AttestationForEdge{
			AttestationNode: vulAttest,
			ForPackage:      log4jPack,
		},
		assembler.VulnerableEdge{
			AttestationNode:   vulAttest,
			VulnerabilityNode: vulNode1,
		},
		assembler.VulnerableEdge{
			AttestationNode:   vulAttest,
			VulnerabilityNode: vulNode2,
		},
		assembler.VulnerableEdge{
			AttestationNode:   vulAttest,
			VulnerabilityNode: vulNode3,
		},
		assembler.VulnerableEdge{
			AttestationNode:   vulAttest,
			VulnerabilityNode: vulNode4,
		},
		assembler.VulnerableEdge{
			AttestationNode:   vulAttest,
			VulnerabilityNode: vulNode5,
		},
		assembler.VulnerableEdge{
			AttestationNode:   vulAttest,
			VulnerabilityNode: vulNode6,
		},
	}
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
		name: "valid vulnerability certifier document",
		doc: &processor.Document{
			Blob:   processor_data.ITE6OSVExmple,
			Format: processor.FormatJSON,
			Type:   processor.DocumentITE6Vul,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantNodes: []assembler.GuacNode{log4jPack, vulAttest, vulNode1, vulNode2, vulNode3, vulNode4, vulNode5, vulNode6},
		wantEdges: osvCertifierEdges,
		wantErr:   false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewOSVCertificationParser()
			err := s.Parse(ctx, tt.doc)
			if (err != nil) != tt.wantErr {
				t.Errorf("osvCertificationParser.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if nodes := s.CreateNodes(ctx); !testdata.GuacNodeSliceEqual(nodes, tt.wantNodes) {
				t.Errorf("osvCertificationParser.CreateNodes() = %v, want %v", nodes, tt.wantNodes)
			}
			if edges := s.CreateEdges(ctx, nil); !testdata.GuacEdgeSliceEqual(edges, tt.wantEdges) {
				t.Errorf("osvCertificationParser.CreateEdges() = %v, want %v", edges, tt.wantEdges)
			}
		})
	}
}
