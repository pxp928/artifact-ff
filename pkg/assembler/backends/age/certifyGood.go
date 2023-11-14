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

// query certifyGood

func (c *ageClient) CertifyGood(ctx context.Context, certifyGoodSpec *model.CertifyGoodSpec) ([]*model.CertifyGood, error) {
	return nil, nil
}

func setCertifyGoodValues(sb *strings.Builder, certifyGoodSpec *model.CertifyGoodSpec, firstMatch *bool, queryValues map[string]any) {
	if certifyGoodSpec.Justification != nil {
		matchProperties(sb, *firstMatch, "certifyGood", "justification", "$justification")
		*firstMatch = false
		queryValues["justification"] = certifyGoodSpec.Justification
	}
	if certifyGoodSpec.Origin != nil {
		matchProperties(sb, *firstMatch, "certifyGood", "origin", "$origin")
		*firstMatch = false
		queryValues["origin"] = certifyGoodSpec.Origin
	}
	if certifyGoodSpec.Collector != nil {
		matchProperties(sb, *firstMatch, "certifyGood", "collector", "$collector")
		*firstMatch = false
		queryValues["collector"] = certifyGoodSpec.Collector
	}
}

func generateModelCertifyGood(subject model.PackageSourceOrArtifact, justification, origin, collector string) *model.CertifyGood {
	certifyGood := model.CertifyGood{
		Subject:       subject,
		Justification: justification,
		Origin:        origin,
		Collector:     collector,
	}
	return &certifyGood
}

// ingest certifyGood

func (c *ageClient) IngestCertifyGood(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyGood model.CertifyGoodInputSpec) (*model.CertifyGood, error) {
	return nil, nil
}

func (c *ageClient) IngestCertifyGoods(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyGoods []*model.CertifyGoodInputSpec) ([]*model.CertifyGood, error) {
	return nil, nil
}
