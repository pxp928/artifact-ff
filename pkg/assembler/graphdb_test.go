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

package assembler

import (
	"testing"

	"github.com/guacsec/guac/pkg/assembler/graphdb"
)

/*
	 var (
		// SPDX Testdata

		topLevelPack = PackageNode{
			Name:   "gcr.io/google-containers/alpine-latest",
			Digest: nil,
			Purl:   "pkg:oci/alpine-latest?repository_url=gcr.io/google-containers",
			CPEs:   nil,
			Tags:   []string{"CONTAINER"},
			NodeData: *NewObjectMetadata(
				processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			),
		}

		baselayoutPack = PackageNode{
			Name:    "alpine-baselayout",
			Digest:  nil,
			Purl:    "pkg:alpine/alpine-baselayout@3.2.0-r22?arch=x86_64&upstream=alpine-baselayout&distro=alpine-3.16.2",
			Version: "3.2.0-r22",
			CPEs: []string{
				"cpe:2.3:a:alpine-baselayout:alpine-baselayout:3.2.0-r22:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine-baselayout:alpine_baselayout:3.2.0-r22:*:*:*:*:*:*:*",
			},
			NodeData: *NewObjectMetadata(
				processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			),
		}

		keysPack = PackageNode{
			Name:    "alpine-keys",
			Digest:  nil,
			Purl:    "pkg:alpine/alpine-keys@2.4-r1?arch=x86_64&upstream=alpine-keys&distro=alpine-3.16.2",
			Version: "2.4-r1",
			CPEs: []string{
				"cpe:2.3:a:alpine-keys:alpine-keys:2.4-r1:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine-keys:alpine_keys:2.4-r1:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine:alpine-keys:2.4-r1:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine:alpine_keys:2.4-r1:*:*:*:*:*:*:*",
			},
			NodeData: *NewObjectMetadata(
				processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			),
		}

		baselayoutdataPack = PackageNode{
			Name:    "alpine-baselayout-data",
			Digest:  nil,
			Purl:    "pkg:alpine/alpine-baselayout-data@3.2.0-r22?arch=x86_64&upstream=alpine-baselayout&distro=alpine-3.16.2",
			Version: "3.2.0-r22",
			CPEs: []string{
				"cpe:2.3:a:alpine-baselayout-data:alpine-baselayout-data:3.2.0-r22:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine-baselayout-data:alpine_baselayout_data:3.2.0-r22:*:*:*:*:*:*:*",
			},
			NodeData: *NewObjectMetadata(
				processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			),
		}

		worldFile = ArtifactNode{
			Name:   "/etc/apk/world",
			Digest: "sha256:713e3907167dce202d7c16034831af3d670191382a3e9026e0ac0a4023013201",
			Tags:   []string{"TEXT"},
			NodeData: *NewObjectMetadata(
				processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			),
		}
		rootFile = ArtifactNode{
			Name:   "/etc/crontabs/root",
			Digest: "sha256:575d810a9fae5f2f0671c9b2c0ce973e46c7207fbe5cb8d1b0d1836a6a0470e3",
			Tags:   []string{"TEXT"},
			NodeData: *NewObjectMetadata(
				processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			),
		}
		triggersFile = ArtifactNode{
			Name:   "/lib/apk/db/triggers",
			Digest: "sha256:5415cfe5f88c0af38df3b7141a3f9bc6b8178e9cf72d700658091b8f5539c7b4",
			Tags:   []string{"TEXT"},
			NodeData: *NewObjectMetadata(
				processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			),
		}
		rsaPubFile = ArtifactNode{
			Name:   "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-58cbb476.rsa.pub",
			Digest: "sha256:9a4cd858d9710963848e6d5f555325dc199d1c952b01cf6e64da2c15deedbd97",
			Tags:   []string{"TEXT"},
			NodeData: *NewObjectMetadata(
				processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			),
		}

		spdxNodes = []GuacNode{topLevelPack, baselayoutPack, baselayoutdataPack, rsaPubFile, keysPack, worldFile, rootFile, triggersFile}
		spdxEdges = []GuacEdge{
			DependsOnEdge{
				PackageNode:       topLevelPack,
				PackageDependency: baselayoutPack,
			},
			DependsOnEdge{
				PackageNode:       topLevelPack,
				PackageDependency: baselayoutdataPack,
			},
			DependsOnEdge{
				PackageNode:       topLevelPack,
				PackageDependency: keysPack,
			},
			DependsOnEdge{
				PackageNode:        topLevelPack,
				ArtifactDependency: worldFile,
			},
			DependsOnEdge{
				PackageNode:        topLevelPack,
				ArtifactDependency: rootFile,
			},
			DependsOnEdge{
				PackageNode:        topLevelPack,
				ArtifactDependency: triggersFile,
			},
			DependsOnEdge{
				PackageNode:        topLevelPack,
				ArtifactDependency: rsaPubFile,
			},
			DependsOnEdge{
				PackageNode:       baselayoutPack,
				PackageDependency: keysPack,
			},
			DependsOnEdge{
				ArtifactNode:       rootFile,
				ArtifactDependency: rsaPubFile,
			},
			ContainsEdge{
				PackageNode:       baselayoutPack,
				ContainedArtifact: rootFile,
			},
			ContainsEdge{
				PackageNode:       keysPack,
				ContainedArtifact: rsaPubFile,
			},
		}

		spdxGraphInput = []AssemblerInput{{
			Nodes: spdxNodes,
			Edges: spdxEdges,
		}}

)
*/
func TestStoreGraph(t *testing.T) {
	type args struct {
		g      Graph
		client graphdb.Client
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := StoreGraph(tt.args.g, tt.args.client); (err != nil) != tt.wantErr {
				t.Errorf("StoreGraph() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

/*
func TestSubscribe(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	natsTest := nats_test.NewNatsTestServer()
	url, err := natsTest.EnableJetStreamForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer natsTest.Shutdown()

	jetStream := emitter.NewJetStream(url, "", "")
	ctx, err = jetStream.JetStreamInit(ctx)
	if err != nil {
		t.Fatalf("unexpected error initializing jetstream: %v", err)
	}
	err = jetStream.RecreateStream(ctx)
	if err != nil {
		t.Fatalf("unexpected error recreating jetstream: %v", err)
	}
	defer jetStream.Close()

	testCases := []struct {
		name            string
		assemblerInputs []AssemblerInput
		wantErr         bool
	}{{
		name:            "valid big SPDX document",
		assemblerInputs: spdxGraphInput,
		wantErr:         false,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			testPublish(ctx, tt.assemblerInputs)

			var cancel context.CancelFunc

			ctx, cancel = context.WithTimeout(ctx, time.Second)
			defer cancel()

			errChan := make(chan error, 1)
			defer close(errChan)
			go func() {
				errChan <- Subscribe(ctx)
			}()

			numSubscribers := 1
			subscribersDone := 0

			for subscribersDone < numSubscribers {
				err := <-errChan
				if err != nil && !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("nats emitter Subscribe test errored = %v", err)
				}
				subscribersDone += 1
			}
		})
	}
}

func testPublish(ctx context.Context, assemblerInputs []Graph) error {
	js := emitter.FromContext(ctx)
	assemblerInputsJSON, err := json.Marshal(assemblerInputs)
	if err != nil {
		return err
	}
	_, err = js.Publish(emitter.SubjectNameDocParsed, assemblerInputsJSON)
	if err != nil {
		return err
	}
	return nil
}
*/
