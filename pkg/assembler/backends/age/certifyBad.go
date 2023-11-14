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

package neo4j

import (
	"context"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// query certifyBad

func (c *ageClient) CertifyBad(ctx context.Context, certifyBadSpec *model.CertifyBadSpec) ([]*model.CertifyBad, error) {
	return nil, nil
}

func setCertifyBadValues(sb *strings.Builder, certifyBadSpec *model.CertifyBadSpec, firstMatch *bool, queryValues map[string]any) {
	if certifyBadSpec.Justification != nil {
		matchProperties(sb, *firstMatch, "certifyBad", "justification", "$justification")
		*firstMatch = false
		queryValues["justification"] = certifyBadSpec.Justification
	}
	if certifyBadSpec.Origin != nil {
		matchProperties(sb, *firstMatch, "certifyBad", "origin", "$origin")
		*firstMatch = false
		queryValues["origin"] = certifyBadSpec.Origin
	}
	if certifyBadSpec.Collector != nil {
		matchProperties(sb, *firstMatch, "certifyBad", "collector", "$collector")
		*firstMatch = false
		queryValues["collector"] = certifyBadSpec.Collector
	}
}

func generateModelCertifyBad(subject model.PackageSourceOrArtifact, justification, origin, collector string) *model.CertifyBad {
	certifyBad := model.CertifyBad{
		Subject:       subject,
		Justification: justification,
		Origin:        origin,
		Collector:     collector,
	}
	return &certifyBad
}

// ingest certifyBad

func (c *ageClient) IngestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyBad model.CertifyBadInputSpec) (*model.CertifyBad, error) {
	return nil, nil
}

func (c *ageClient) IngestCertifyBads(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyBads []*model.CertifyBadInputSpec) ([]*model.CertifyBad, error) {
	return nil, nil
}
