//
// Copyright 2023 The GUAC Authors.
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

package arangodb

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestHasMetadata(t *testing.T) {
	ctx := context.Background()
	arangoArgs := getArangoConfig()
	err := deleteDatabase(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	type call struct {
		Sub   model.PackageSourceOrArtifactInput
		Match *model.MatchFlags
		HM    *model.HasMetadataInputSpec
	}
	tests := []struct {
		Name          string
		InPkg         []*model.PkgInputSpec
		InSrc         []*model.SourceInputSpec
		InArt         []*model.ArtifactInputSpec
		Calls         []call
		Query         *model.HasMetadataSpec
		QueryID       bool
		QueryPkgID    bool
		QuerySourceID bool
		QueryArtID    bool
		ExpHM         []*model.HasMetadata
		ExpIngestErr  bool
		ExpQueryErr   bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Key:           "key1",
						Value:         "value1",
						Timestamp:     time.Unix(1e9, 0),
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Key:           ptrfrom.String("key1"),
				Value:         ptrfrom.String("value1"),
				Since:         ptrfrom.Time(time.Unix(1e9, 0)),
				Justification: ptrfrom.String("test justification"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.P1out,
					Key:           "key1",
					Value:         "value1",
					Timestamp:     time.Unix(1e9, 0),
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "HappyPath check time since",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Key:           "key1",
						Value:         "value1",
						Timestamp:     time.Unix(1e9, 0),
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Key:           ptrfrom.String("key1"),
				Value:         ptrfrom.String("value1"),
				Since:         ptrfrom.Time(time.Unix(1e8, 0)),
				Justification: ptrfrom.String("test justification"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.P1out,
					Key:           "key1",
					Value:         "value1",
					Timestamp:     time.Unix(1e9, 0),
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "UnhappyPath check time since",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Key:           "key1",
						Value:         "value1",
						Timestamp:     time.Unix(1e9, 0),
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Key:           ptrfrom.String("key1"),
				Value:         ptrfrom.String("value1"),
				Since:         ptrfrom.Time(time.Unix(1e10, 0)),
				Justification: ptrfrom.String("test justification"),
			},
			ExpHM: nil,
		},
		{
			Name:  "HappyPath All Version",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.P1out,
					Key:           "key1",
					Value:         "value1",
					Timestamp:     time.Unix(1e9, 0),
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest same twice",
			InPkg: []*model.PkgInputSpec{testdata.P3},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P3,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P3,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
						Subpath: ptrfrom.String("saved_model_cli.py"),
					},
				},
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.P3out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest two different keys - query key",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Key:           "key1",
						Value:         "value1",
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Key:           "key2",
						Value:         "value2",
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Key: ptrfrom.String("key2"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.P1out,
					Key:           "key2",
					Value:         "value2",
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest two different keys - query value",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Key:           "key1",
						Value:         "value1",
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Key:           "key2",
						Value:         "value2",
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Value: ptrfrom.String("value1"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.P1out,
					Key:           "key1",
					Value:         "value1",
					Timestamp:     time.Unix(1e9, 0),
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1out,
					Key:           "key1",
					Value:         "value1",
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Justification",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification one",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification two",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Justification: ptrfrom.String("test justification one"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.P1out,
					Justification: "test justification one",
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P4},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P4,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Type:      ptrfrom.String("conan"),
						Namespace: ptrfrom.String("openssl.org"),
						Name:      ptrfrom.String("openssl"),
					},
				},
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.P4out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Package version ID",
			InPkg: []*model.PkgInputSpec{testdata.P4},
			InSrc: []*model.SourceInputSpec{},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P4,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			QueryPkgID: true,
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.P4out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Source",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1, testdata.S2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S2,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Source: &model.SourceSpec{
						Name: ptrfrom.String("bobsrepo"),
					},
				},
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.S2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Source ID",
			InPkg: []*model.PkgInputSpec{},
			InSrc: []*model.SourceInputSpec{testdata.S2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S2,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			QuerySourceID: true,
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.S2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Artifact",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha1"),
					},
				},
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.A2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Artifact ID",
			InSrc: []*model.SourceInputSpec{},
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			QueryArtID: true,
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.A2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query none",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("asdf"),
					},
				},
			},
			ExpHM: nil,
		},
		{
			Name:  "Query multiple",
			InSrc: []*model.SourceInputSpec{testdata.S1, testdata.S2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S2,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Source: &model.SourceSpec{
						Type: ptrfrom.String("git"),
					},
				}},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.S2out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.S1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query Packages",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P4},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P2,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P4,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Name:    ptrfrom.String("openssl"),
						Version: ptrfrom.String("3.0.3"),
					},
				},
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.P4out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P4outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query ID",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			QueryID: true,
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.A2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query bad ID",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				ID: ptrfrom.String("asdf"),
			},
			ExpQueryErr: true,
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, p := range test.InPkg {
				if pkgIDs, err := b.IngestPackageID(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				} else {
					if test.QueryPkgID {
						test.Query = &model.HasMetadataSpec{
							Subject: &model.PackageSourceOrArtifactSpec{
								Package: &model.PkgSpec{
									ID: ptrfrom.String(pkgIDs.PackageVersionID),
								},
							},
						}
					}
				}
			}
			for _, s := range test.InSrc {
				if srcIDs, err := b.IngestSourceID(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				} else {
					if test.QuerySourceID {
						test.Query = &model.HasMetadataSpec{
							Subject: &model.PackageSourceOrArtifactSpec{
								Source: &model.SourceSpec{
									ID: ptrfrom.String(srcIDs.SourceNameID),
								},
							},
						}
					}
				}
			}
			for _, a := range test.InArt {
				if artID, err := b.IngestArtifactID(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				} else {
					if test.QueryArtID {
						test.Query = &model.HasMetadataSpec{
							Subject: &model.PackageSourceOrArtifactSpec{
								Artifact: &model.ArtifactSpec{
									ID: ptrfrom.String(artID),
								},
							},
						}
					}
				}
			}
			for _, o := range test.Calls {
				hmID, err := b.IngestHasMetadataID(ctx, o.Sub, o.Match, *o.HM)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.HasMetadataSpec{
						ID: ptrfrom.String(hmID),
					}
				}
			}
			got, err := b.HasMetadata(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpHM, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestBulkHasMetadata(t *testing.T) {
	ctx := context.Background()
	arangoArgs := getArangoConfig()
	err := deleteDatabase(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	type call struct {
		Sub   model.PackageSourceOrArtifactInputs
		Match *model.MatchFlags
		HM    []*model.HasMetadataInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		Query        *model.HasMetadataSpec
		ExpHM        []*model.HasMetadata
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.P1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "HappyPath All Version",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.P1out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest same twice",
			InPkg: []*model.PkgInputSpec{testdata.P3},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P3, testdata.P3},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
						Subpath: ptrfrom.String("saved_model_cli.py"),
					},
				},
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.P3out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P4},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P4},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Sources: []*model.SourceInputSpec{testdata.S1},
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Type:      ptrfrom.String("conan"),
						Namespace: ptrfrom.String("openssl.org"),
						Name:      ptrfrom.String("openssl"),
					},
				},
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.P4out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Source",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1, testdata.S2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Sources: []*model.SourceInputSpec{testdata.S2, testdata.S2},
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Source: &model.SourceSpec{
						Name: ptrfrom.String("bobsrepo"),
					},
				},
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.S2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Artifact",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Artifacts: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Sources: []*model.SourceInputSpec{testdata.S1},
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha1"),
					},
				},
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       testdata.A2out,
					Justification: "test justification",
				},
			},
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, p := range test.InPkg {
				if _, err := b.IngestPackageID(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, s := range test.InSrc {
				if _, err := b.IngestSourceID(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, a := range test.InArt {
				if _, err := b.IngestArtifactID(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, o := range test.Calls {
				_, err := b.IngestBulkHasMetadata(ctx, o.Sub, o.Match, o.HM)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.HasMetadata(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpHM, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_buildHasMetadataByID(t *testing.T) {
	ctx := context.Background()
	arangoArgs := getArangoConfig()
	err := deleteDatabase(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	type call struct {
		Sub   model.PackageSourceOrArtifactInput
		Match *model.MatchFlags
		HM    *model.HasMetadataInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		Query        *model.HasMetadataSpec
		ExpHM        *model.HasMetadata
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{testdata.P4},
			InSrc: []*model.SourceInputSpec{},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P4,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Type:      ptrfrom.String("conan"),
						Namespace: ptrfrom.String("openssl.org"),
						Name:      ptrfrom.String("openssl"),
					},
				},
			},
			ExpHM: &model.HasMetadata{
				Subject:       testdata.P4out,
				Justification: "test justification",
			},
		},
		{
			Name:  "Query on Package without filter",
			InPkg: []*model.PkgInputSpec{testdata.P4},
			InSrc: []*model.SourceInputSpec{},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P4,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpHM: &model.HasMetadata{
				Subject:       testdata.P4out,
				Justification: "test justification",
			},
		},
		{
			Name:  "Query on Source",
			InSrc: []*model.SourceInputSpec{testdata.S2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S2,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Source: &model.SourceSpec{
						Name: ptrfrom.String("bobsrepo"),
					},
				},
			},
			ExpHM: &model.HasMetadata{
				Subject:       testdata.S2out,
				Justification: "test justification",
			},
		},
		{
			Name:  "Query on Source without filter",
			InSrc: []*model.SourceInputSpec{testdata.S2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S2,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpHM: &model.HasMetadata{

				Subject:       testdata.S2out,
				Justification: "test justification",
			},
		},
		{
			Name:  "Query on Artifact",
			InArt: []*model.ArtifactInputSpec{testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha1"),
					},
				},
			},
			ExpHM: &model.HasMetadata{
				Subject:       testdata.A2out,
				Justification: "test justification",
			},
		},
		{
			Name:  "Query on Artifact without filter",
			InSrc: []*model.SourceInputSpec{},
			InArt: []*model.ArtifactInputSpec{testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpHM: &model.HasMetadata{
				Subject:       testdata.A2out,
				Justification: "test justification",
			},
		},
		{
			Name:  "Query ID",
			InArt: []*model.ArtifactInputSpec{testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpHM: &model.HasMetadata{
				Subject:       testdata.A2out,
				Justification: "test justification",
			},
		},
		{
			Name:  "Query bad ID",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				ID: ptrfrom.String("asdf"),
			},
			ExpQueryErr: true,
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, p := range test.InPkg {
				if _, err := b.IngestPackageID(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, s := range test.InSrc {
				if _, err := b.IngestSourceID(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, a := range test.InArt {
				if _, err := b.IngestArtifactID(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, o := range test.Calls {
				hsID, err := b.IngestHasMetadataID(ctx, o.Sub, o.Match, *o.HM)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				got, err := b.(*arangoClient).buildHasMetadataByID(ctx, hsID, test.Query)
				if (err != nil) != test.ExpQueryErr {
					t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
				}
				if err != nil {
					return
				}
				if diff := cmp.Diff(test.ExpHM, got, ignoreID); diff != "" {
					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
				}
			}

		})
	}
}
