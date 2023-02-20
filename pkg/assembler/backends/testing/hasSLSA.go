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

package testing

import (
	"context"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func registerAllHasSLSA(client *demoClient) error {
	// pkg:pypi/django@1.11.1
	// client.registerPackage("pypi", "", "django", "1.11.1", "")
	selectedType := "pypi"
	selectedNameSpace := ""
	selectedName := "django"
	selectedVersion := "1.11.1"
	selectedSubpath := ""
	selectedPkgSpec := &model.PkgSpec{Type: &selectedType, Namespace: &selectedNameSpace, Name: &selectedName, Version: &selectedVersion, Subpath: &selectedSubpath}
	selectedPackage, err := client.Packages(context.TODO(), selectedPkgSpec)
	if err != nil {
		return err
	}

	// "git", "github", "https://github.com/django/django", "tag=1.11.1"
	selectedSourceType := "git"
	selectedSourceNameSpace := "github"
	selectedSourceName := "https://github.com/django/django"
	selectedTag := "1.11.1"
	selectedSourceQualifiers := &model.SourceQualifierInput{Tag: &selectedTag}
	selectedSourceSpec := &model.SourceSpec{Type: &selectedSourceType, Namespace: &selectedSourceNameSpace, Name: &selectedSourceName, Qualifier: selectedSourceQualifiers}
	selectedSource, err := client.Sources(context.TODO(), selectedSourceSpec)
	if err != nil {
		return err
	}
	predicateValues := []*model.SLSAPredicate{{Key: "buildDefinition.externalParameters.repository", Value: "https://github.com/octocat/hello-world"}, {Key: "buildDefinition.externalParameters.ref", Value: "refs/heads/main"}, {Key: "buildDefinition.resolvedDependencies.uri", Value: "git+https://github.com/octocat/hello-world@refs/heads/main"}}

	err = client.registerHasSLSA(selectedPackage[0], nil, nil, nil, selectedSource, nil, &model.Builder{URI: "https://github.com/Attestations/GitHubHostedActions@v1"}, "https://github.com/Attestations/GitHubActionsWorkflow@v1", predicateValues, "v1", time.Now().String(), time.Now().String())
	if err != nil {
		return err
	}
	return nil
}

// Ingest HasSlsa

func (c *demoClient) registerHasSLSA(selectedPackage *model.Package, selectedSource *model.Source, selectedArtifact *model.Artifact, builtFromPackages []*model.Package,
	builtFromSouces []*model.Source, builtFromArtifacts []*model.Artifact, builtBy *model.Builder, buildType string, predicate []*model.SLSAPredicate, slsaVersion string, startOn string, finishOn string) error {

	/*
	  subject: PkgSrcArtObject!
	  builtFrom: [PkgSrcArtObject!]!
	  builtBy: Builder!
	  buildType: String!
	  predicate: [Predicate!]!
	  slsaVersion: String!
	  startedOn: String!
	  finishedOn: String!
	  origin: String!
	  collector: String!
	*/

	for _, h := range c.hasSLSA {
		if h.BuildType == buildType && h.SlsaVersion == slsaVersion {
			if val, ok := h.Subject.(model.Package); ok {
				if &val == selectedPackage {
					return nil
				}
			} else if val, ok := h.Subject.(model.Source); ok {
				if &val == selectedSource {
					return nil
				}
			} else if val, ok := h.Subject.(model.Artifact); ok {
				if &val == selectedArtifact {
					return nil
				}
			}
		}
	}

	newHasSlsa := &model.HasSlsa{
		BuiltBy:       builtBy,
		BuildType:     buildType,
		SlsaPredicate: predicate,
		SlsaVersion:   slsaVersion,
		StartedOn:     startOn,
		FinishedOn:    finishOn,
		Origin:        "testing backend",
		Collector:     "testing backend",
	}
	if selectedPackage != nil {
		newHasSlsa.Subject = selectedPackage
	} else if selectedSource != nil {
		newHasSlsa.Subject = selectedSource
	} else {
		newHasSlsa.Subject = selectedArtifact
	}

	for _, pack := range builtFromPackages {
		newHasSlsa.BuiltFrom = append(newHasSlsa.BuiltFrom, pack)
	}
	for _, source := range builtFromSouces {
		newHasSlsa.BuiltFrom = append(newHasSlsa.BuiltFrom, source)
	}
	for _, art := range builtFromArtifacts {
		newHasSlsa.BuiltFrom = append(newHasSlsa.BuiltFrom, art)
	}

	c.hasSLSA = append(c.hasSLSA, newHasSlsa)
	return nil
}

// Query HasSlsa

func (c *demoClient) HasSlsa(ctx context.Context, hasSLSASpec *model.HasSLSASpec) ([]*model.HasSlsa, error) {

	if hasSLSASpec.Package != nil && hasSLSASpec.Source != nil && hasSLSASpec.Artifact != nil {
		return nil, gqlerror.Errorf("cannot specify package, source and artifact together for hasSLSASpec")
	}
	if hasSLSASpec.Package != nil && hasSLSASpec.Source != nil {
		return nil, gqlerror.Errorf("cannot specify package and source together for hasSLSASpec")
	}
	if hasSLSASpec.Package != nil && hasSLSASpec.Artifact != nil {
		return nil, gqlerror.Errorf("cannot specify package and artifact together for hasSLSASpec")
	}
	if hasSLSASpec.Source != nil && hasSLSASpec.Artifact != nil {
		return nil, gqlerror.Errorf("cannot specify source and artifact together for hasSLSASpec")
	}

	var collectedHasSLSA []*model.HasSlsa

	/*
	  subject: PkgSrcArtObject!
	  builtFrom: [PkgSrcArtObject!]!
	  builtBy: Builder!
	  buildType: String!
	  predicate: [Predicate!]!
	  slsaVersion: String!
	  startedOn: String!
	  finishedOn: String!
	  origin: String!
	  collector: String!
	*/

	for _, h := range c.hasSLSA {
		buildTypeMatchOrSkip := false
		collectorMatchOrSkip := false
		originMatchOrSkip := false
		packageMatchOrSkip := false
		sourceMatchOrSkip := false
		artifactMatchOrSkip := false
		builtByMatchOrSkip := false
		slsaVersionMatchOrSkip := false

		if hasSLSASpec.BuildType == nil || h.BuildType == *hasSLSASpec.BuildType {
			buildTypeMatchOrSkip = true
		}
		if hasSLSASpec.SlsaVersion == nil || h.SlsaVersion == *hasSLSASpec.SlsaVersion {
			slsaVersionMatchOrSkip = true
		}
		if hasSLSASpec.Collector == nil || h.Collector == *hasSLSASpec.Collector {
			collectorMatchOrSkip = true
		}
		if hasSLSASpec.Origin == nil || h.Origin == *hasSLSASpec.Origin {
			originMatchOrSkip = true
		}

		if hasSLSASpec.BuiltBy == nil {
			builtByMatchOrSkip = true
		} else if hasSLSASpec.BuiltBy != nil && h.BuiltBy != nil {
			if hasSLSASpec.BuiltBy.URI == nil || h.BuiltBy.URI == *hasSLSASpec.BuiltBy.URI {
				builtByMatchOrSkip = true
			}
		}

		if hasSLSASpec.Package == nil {
			packageMatchOrSkip = true
		} else if hasSLSASpec.Package != nil && h.Subject != nil {
			if val, ok := h.Subject.(*model.Package); ok {
				if hasSLSASpec.Package.Type == nil || val.Type == *hasSLSASpec.Package.Type {
					newPkg := filterPackageNamespace(val, hasSLSASpec.Package)
					if newPkg != nil {
						packageMatchOrSkip = true
					}
				}
			}
		}

		if hasSLSASpec.Source == nil {
			sourceMatchOrSkip = true
		} else if hasSLSASpec.Source != nil && h.Subject != nil {
			if val, ok := h.Subject.(*model.Source); ok {
				if hasSLSASpec.Source.Type == nil || val.Type == *hasSLSASpec.Source.Type {
					newSource, err := filterSourceNamespace(val, hasSLSASpec.Source)
					if err != nil {
						return nil, err
					}
					if newSource != nil {
						sourceMatchOrSkip = true
					}
				}
			}
		}

		if hasSLSASpec.Artifact == nil {
			artifactMatchOrSkip = true
		} else if hasSLSASpec.Artifact != nil && h.Subject != nil {
			if val, ok := h.Subject.(*model.Artifact); ok {
				queryArt := &model.Artifact{
					Algorithm: strings.ToLower(*hasSLSASpec.Artifact.Algorithm),
					Digest:    strings.ToLower(*hasSLSASpec.Artifact.Digest),
				}
				if *queryArt == *val {
					artifactMatchOrSkip = true
				}
			}
		}

		if buildTypeMatchOrSkip && collectorMatchOrSkip && originMatchOrSkip && packageMatchOrSkip && sourceMatchOrSkip && artifactMatchOrSkip &&
			builtByMatchOrSkip && slsaVersionMatchOrSkip {
			collectedHasSLSA = append(collectedHasSLSA, h)
		}
	}

	return collectedHasSLSA, nil
}
