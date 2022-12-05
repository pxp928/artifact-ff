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

package process

import (
	"context"
	"testing"
	"time"

	"github.com/guacsec/guac/internal/testing/ingestor/simpledoc"
	nats_test "github.com/guacsec/guac/internal/testing/nats"
	testdata "github.com/guacsec/guac/internal/testing/processor"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/guesser"
)

func Test_SimpleDocProcessTest(t *testing.T) {
	natsTest := nats_test.NewNatsTestServer()
	url, err := natsTest.EnableJetStreamForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer natsTest.Shutdown()

	ctx := context.Background()
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
		name      string
		doc       processor.Document
		expected  processor.DocumentTree
		expectErr bool
	}{{

		name: "simple test",
		doc: processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		expected: testdata.DocNode(&processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		}),
	}, {

		name: "unpack test",
		doc: processor.Document{
			Blob: []byte(`{
						 "issuer": "google.com",
						 "info": "this is a cool document",
						 "nested": [{
							 "issuer": "google.com",
							 "info": "this is a cooler nested doc 1"
						 },{
							 "issuer": "google.com",
							 "info": "this is a cooler nested doc 2"
						 }]
						}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		expected: testdata.DocNode(
			&processor.Document{ //root
				Blob: []byte(`{
                           "issuer": "google.com",
                           "info": "this is a cool document",
                           "nested": [{
                               "issuer": "google.com",
                               "info": "this is a cooler nested doc 1"
                           },{
                               "issuer": "google.com",
                               "info": "this is a cooler nested doc 2"
                           }]
                          }`),
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			},
			testdata.DocNode(&processor.Document{ // child 1
				Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cooler nested doc 1"
					}`),
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			}),
			testdata.DocNode(&processor.Document{ //child 2
				Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cooler nested doc 2"
					}`),
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			})),
	}, {

		name: "unpack twice test",
		doc: processor.Document{
			Blob: []byte(`{
						 "issuer": "google.com",
						 "info": "this is a cool document",
						 "nested": [{
							 "issuer": "google.com",
							 "info": "this is a cooler nested doc 1",
							 "nested": [{
							   "issuer": "google.com",
							   "info": "this is a cooler nested doc 3"
							 }]
						 },{
							 "issuer": "google.com",
							 "info": "this is a cooler nested doc 2",
							 "nested": [{
							   "issuer": "google.com",
							   "info": "this is a cooler nested doc 4"
							 }]
						 }]
						}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		expected: testdata.DocNode(
			&processor.Document{ // root
				Blob: []byte(`{
                           "issuer": "google.com",
                           "info": "this is a cool document",
                           "nested": [{
                               "issuer": "google.com",
                               "info": "this is a cooler nested doc 1",
                               "nested": [{
                                 "issuer": "google.com",
                                 "info": "this is a cooler nested doc 3"
                               }]
                           },{
                               "issuer": "google.com",
                               "info": "this is a cooler nested doc 2",
                               "nested": [{
                                 "issuer": "google.com",
                                 "info": "this is a cooler nested doc 4"
                               }]
                           }]
                          }`),
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			},
			testdata.DocNode(&processor.Document{
				Blob: []byte(`{
							"issuer": "google.com",
							 "info": "this is a cooler nested doc 1",
							 "nested": [{
							   "issuer": "google.com",
							   "info": "this is a cooler nested doc 3"
							 }]
							 }`),
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			},
				testdata.DocNode(&processor.Document{
					Blob: []byte(`{
                        "issuer": "google.com",
                        "info": "this is a cooler nested doc 3"
                    }`),
					Type:              simpledoc.SimpleDocType,
					Format:            processor.FormatJSON,
					SourceInformation: processor.SourceInformation{},
				})),
			testdata.DocNode(&processor.Document{
				Blob: []byte(`{
                              "issuer": "google.com",
                               "info": "this is a cooler nested doc 2",
                               "nested": [{
                                 "issuer": "google.com",
                                 "info": "this is a cooler nested doc 4"
                               }]
                               }`),
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			},
				testdata.DocNode(&processor.Document{
					Blob: []byte(`{
                        "issuer": "google.com",
                        "info": "this is a cooler nested doc 4"
                    }`),
					Type:              simpledoc.SimpleDocType,
					Format:            processor.FormatJSON,
					SourceInformation: processor.SourceInformation{},
				}))),
	}, {

		name: "unpack assymetric test",
		doc: processor.Document{
			Blob: []byte(`{
				 "issuer": "google.com",
				 "info": "this is a cool document",
				 "nested": [{
					 "issuer": "google.com",
					 "info": "this is a cooler nested doc 1"
				 },{
					 "issuer": "google.com",
					 "info": "this is a cooler nested doc 2",
					 "nested": [{
					   "issuer": "google.com",
					   "info": "this is a cooler nested doc 4"
					 }]
				 }]
				}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		expected: testdata.DocNode(
			&processor.Document{ //root
				Blob: []byte(`{
                   "issuer": "google.com",
                   "info": "this is a cool document",
                   "nested": [{
                       "issuer": "google.com",
                       "info": "this is a cooler nested doc 1"
                   },{
                       "issuer": "google.com",
                       "info": "this is a cooler nested doc 2",
                       "nested": [{
                         "issuer": "google.com",
                         "info": "this is a cooler nested doc 4"
                       }]
                   }]
                  }`),
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			},
			testdata.DocNode(&processor.Document{ // child 1
				Blob: []byte(`{
				"issuer": "google.com",
				"info": "this is a cooler nested doc 1"
			}`),
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			}),
			testdata.DocNode(&processor.Document{ // child 2
				Blob: []byte(`{
				"issuer": "google.com",
				"info": "this is a cooler nested doc 2",
				"nested": [{
				   "issuer": "google.com",
				   "info": "this is a cooler nested doc 4"
				 }]
				}`),
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			},
				testdata.DocNode(&processor.Document{ // child 2.1
					Blob: []byte(`{
                  "issuer": "google.com",
                  "info": "this is a cooler nested doc 4"
                  }`),
					Type:              simpledoc.SimpleDocType,
					Format:            processor.FormatJSON,
					SourceInformation: processor.SourceInformation{},
				})),
		),
	}, {

		name: "bad format",
		doc: processor.Document{
			Blob: []byte(`{ NOT JSON YO
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}, {

		name: "bad format type",
		doc: processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              simpledoc.SimpleDocType,
			Format:            "invalid-format",
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}, {

		name: "bad document schema",
		doc: processor.Document{
			// simpledoc requires issuer
			Blob: []byte(`{
                        "info": "this is a cool document"
                    }`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}, {

		name: "bad schema type",
		doc: processor.Document{
			Blob: []byte(`{
                        "issuer": "google.com",
                        "info": "this is a cool document"
                    }`),
			Type:              "invalid-document-type",
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}, {

		name: "unknown format",
		doc: processor.Document{
			Blob: []byte(`{ NOT JSON YO
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}, {

		name: "unknown document",
		doc: processor.Document{
			Blob: []byte(`{
						"abc": "def"
					}`),
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}, {

		// misc
		name: "propagate source info",
		doc: processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:   simpledoc.SimpleDocType,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector: "a-collector",
				Source:    "a-source",
			},
		},
		expected: testdata.DocNode(&processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:   simpledoc.SimpleDocType,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector: "a-collector",
				Source:    "a-source",
			},
		}),
	}, {

		// misc
		name: "propagate nested source info",
		doc: processor.Document{
			Blob: []byte(`{
                         "issuer": "google.com",
                         "info": "this is a cool document",
                         "nested": [{
                             "issuer": "google.com",
                             "info": "this is a cooler nested doc 1"
                         },{
                             "issuer": "google.com",
                             "info": "this is a cooler nested doc 2"
                         }]
                        }`),
			Type:   simpledoc.SimpleDocType,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector: "a-collector",
				Source:    "a-source",
			},
		},
		expected: testdata.DocNode(
			&processor.Document{ //root
				Blob: []byte(`{
                           "issuer": "google.com",
                           "info": "this is a cool document",
                           "nested": [{
                               "issuer": "google.com",
                               "info": "this is a cooler nested doc 1"
                           },{
                               "issuer": "google.com",
                               "info": "this is a cooler nested doc 2"
                           }]
                          }`),
				Type:   simpledoc.SimpleDocType,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "a-collector",
					Source:    "a-source",
				},
			},
			testdata.DocNode(&processor.Document{ //child 1
				Blob: []byte(`{
                        "issuer": "google.com",
                        "info": "this is a cooler nested doc 1"
                    }`),
				Type:   simpledoc.SimpleDocType,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "a-collector",
					Source:    "a-source",
				},
			}),
			testdata.DocNode(&processor.Document{ //child 2
				Blob: []byte(`{
                        "issuer": "google.com",
                        "info": "this is a cooler nested doc 2"
                    }`),
				Type:   simpledoc.SimpleDocType,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "a-collector",
					Source:    "a-source",
				},
			})),
	}, {

		// preprocessor tests
		name: "preprocessor on format JSON",
		doc: processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expected: testdata.DocNode(&processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		}),
	}, {

		name: "preprocessor on simpledoc",
		doc: processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expected: testdata.DocNode(&processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		}),
	},
	}

	// Register
	err = RegisterDocumentProcessor(&simpledoc.SimpleDocProc{}, simpledoc.SimpleDocType)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = guesser.RegisterDocumentTypeGuesser(&simpledoc.SimpleDocProc{}, "simple-doc-guesser")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			docTree, err := Process(ctx, &tt.doc)
			if err != nil {
				if tt.expectErr {
					return
				}
				t.Errorf("unexpected error: %v", err)
				return
			}

			if !testdata.DocTreeEqual(docTree, tt.expected) {
				t.Errorf("doc tree did not match up, got\n%s, \nexpected\n%s", testdata.StringTree(docTree), testdata.StringTree(tt.expected))
			}

			/*
				// Compare docs
				if len(docs) != len(tt.expected) {
					t.Errorf("number of docs got %v, expected %v", len(docs), len(tt.expected))
					return
				}
				for _, d := range docs {
					if !existAndPop(tt.expected, *d) {
						t.Errorf("got doc but not expected: %v", d)
						return
					}
				}
			*/
		})
	}
}

func Test_ProcessSubscribeTest(t *testing.T) {
	natsTest := nats_test.NewNatsTestServer()
	url, err := natsTest.EnableJetStreamForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer natsTest.Shutdown()

	ctx := context.Background()
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
		name      string
		doc       processor.Document
		expectErr bool
	}{{
		name: "simple test",
		doc: processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
	}, {
		name: "unpack test",
		doc: processor.Document{
			Blob: []byte(`{
						 "issuer": "google.com",
						 "info": "this is a cool document",
						 "nested": [{
							 "issuer": "google.com",
							 "info": "this is a cooler nested doc 1"
						 },{
							 "issuer": "google.com",
							 "info": "this is a cooler nested doc 2"
						 }]
						}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
	}, {
		name: "bad format",
		doc: processor.Document{
			Blob: []byte(`{ NOT JSON YO
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}}

	documentProcessors = map[processor.DocumentType]processor.DocumentProcessor{}
	// Register
	err = RegisterDocumentProcessor(&simpledoc.SimpleDocProc{}, simpledoc.SimpleDocType)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	err = guesser.RegisterDocumentTypeGuesser(&simpledoc.SimpleDocProc{}, "simple-doc-guesser")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			collector.Publish(ctx, &tt.doc)
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			go func() {
				err := Subscribe(ctx)
				if err != nil {
					if tt.expectErr {
						return
					}
					t.Errorf("unexpected error: %v", err)
					return
				}
			}()
		})
	}
}
