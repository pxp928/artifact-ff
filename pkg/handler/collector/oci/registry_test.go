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

package oci

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/guacsec/guac/internal/testing/dochelper"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/regclient/regclient/scheme/ocidir"
	"github.com/regclient/regclient/types/ref"
)

func Test_ociRegistryCollector_RetrieveArtifacts(t *testing.T) {
	ctx := context.Background()

	o := ocidir.New()
	// get manifest to lookup config digest
	rs := "ocidir://testdata/regctl:latest"
	rl, err := ref.New(rs)
	if err != nil {
		t.Errorf("failed to parse ref %s: %v", rs, err)
		return
	}
	ml, err := o.ManifestGet(ctx, rl)
	if err != nil {
		t.Errorf("manifest get: %v", err)
		return
	}

	type fields struct {
		registry string
		poll     bool
		interval time.Duration
	}
	tests := []struct {
		name       string
		fields     fields
		wantErr    bool
		errMessage error
		want       []*processor.Document
	}{
		{
			name: "testing",
			fields: fields{
				registry: rs,
				poll:     false,
				interval: time.Second,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := NewOCIRegistryCollector(ctx, tt.fields.registry, tt.fields.poll, tt.fields.interval)

			var cancel context.CancelFunc
			if tt.fields.poll {
				ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
			}

			var err error
			docChan := make(chan *processor.Document, 1)
			errChan := make(chan error, 1)
			defer close(docChan)
			defer close(errChan)
			go func() {
				errChan <- o.RetrieveArtifacts(ctx, docChan)
			}()
			numCollectors := 1
			collectorsDone := 0

			collectedDocs := []*processor.Document{}

			for collectorsDone < numCollectors {
				select {
				case d := <-docChan:
					collectedDocs = append(collectedDocs, d)
				case err = <-errChan:
					if err != nil {
						if !tt.wantErr {
							t.Errorf("o.RetrieveArtifacts() error = %v, wantErr %v", err, tt.wantErr)
							return
						}
						if !strings.Contains(err.Error(), tt.errMessage.Error()) {
							t.Errorf("o.RetrieveArtifacts() error = %v, wantErr %v", err, tt.errMessage)
							return
						}
					}
					collectorsDone += 1
				}
			}
			// Drain anything left in document channel
			for len(docChan) > 0 {
				d := <-docChan
				collectedDocs = append(collectedDocs, d)
			}
			if err == nil {
				for i := range collectedDocs {
					result := dochelper.DocTreeEqual(dochelper.DocNode(collectedDocs[i]), dochelper.DocNode(tt.want[i]))
					if !result {
						t.Errorf("g.RetrieveArtifacts() = %v, want %v", string(collectedDocs[i].Blob), string(tt.want[i].Blob))
					}
				}

				if o.Type() != OCIRegistryCollector {
					t.Errorf("o.Type() = %s, want %s", o.Type(), OCIRepoCollector)
				}
			}

		})
	}
}
