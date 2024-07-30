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

package backend

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/billofmaterials"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvuln"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
)

// FindSoftware takes in a searchText string and looks for software
// that may be relevant for the input text. This can be seen as fuzzy search
// function for Packages, Sources and Artifacts. findSoftware returns a list
// of Packages, Sources and Artifacts that it determines to be relevant to
// the input searchText.

// Due to the nature of full text search being implemented differently on
// different db platforms, the behavior of findSoftware is not guaranteed
// to be the same. In addition, their statistical nature may result in
// results being different per call and not reproducible.

// All that is asked in the implementation of this API is that it follows
// the spirit of helping to retrieve the right nodes with best effort.

// Warning: This is an EXPERIMENTAL feature. This is subject to change.
// Warning: This is an OPTIONAL feature. Backends are not required to
// implement this API.
func (b *EntBackend) FindSoftware(ctx context.Context, searchText string) ([]model.PackageSourceOrArtifact, error) {
	// Arbitrarily only search if the search text is longer than 2 characters
	// Search Artifacts
	results := make([]model.PackageSourceOrArtifact, 0)
	if len(searchText) <= 2 {
		return results, nil
	}

	// Search by Package Name
	packages, err := b.client.PackageVersion.Query().Where(
		packageversion.HasNameWith(
			packagename.NameContainsFold(searchText),
		),
	).WithName(func(q *ent.PackageNameQuery) {}).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed package version query with err: %w", err)
	}

	results = append(results, collect(packages, func(v *ent.PackageVersion) model.PackageSourceOrArtifact {
		return toModelPackage(backReferencePackageVersion(v))
	})...)

	// Search Sources
	sources, err := b.client.SourceName.Query().Where(
		sourcename.Or(
			sourcename.NameContainsFold(searchText),
			sourcename.NamespaceContainsFold(searchText),
		),
	).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed source name query with err: %w", err)
	}
	results = append(results, collect(sources, func(v *ent.SourceName) model.PackageSourceOrArtifact {
		return toModelSource(v)
	})...)

	artifacts, err := b.client.Artifact.Query().Where(
		artifact.DigestContains(searchText),
	).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed artifact query with err: %w", err)
	}

	results = append(results, collect(artifacts, func(v *ent.Artifact) model.PackageSourceOrArtifact {
		return toModelArtifact(v)
	})...)

	return results, nil
}

func (b *EntBackend) FindSoftwareList(ctx context.Context, searchText string, after *string, first *int) (*model.FindSoftwareConnection, error) {
	return nil, fmt.Errorf("not implemented: FindSoftwareList")
}

func (b *EntBackend) FindAllPkgVulnBasedOnSbom(ctx context.Context, hasSBOMID string) ([]model.Node, error) {
	var nodes []model.Node

	sbomQuery := b.client.Debug().BillOfMaterials.Query().
		Where(sbomQuery(hasSBOMID))

	record, err := sbomObjectWithIncludes(sbomQuery).
		Only(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "FindAllPkgVulnBasedOnSbom")
	}

	nodes = append(nodes, toModelHasSBOM(record))

	// entPkgVersions, err := record.IncludedSoftwarePackages(ctx)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to get included packages with error: %w", err)
	// }

	// for _, pNode := range entPkgVersions {
	// 	//nodes = append(nodes, toModelPackage(backReferencePackageVersion(pNode)))
	// 	certVulns, err := b.CertifyVuln(ctx, &model.CertifyVulnSpec{Package: &model.PkgSpec{ID: ptrfrom.String(pkgVersionGlobalID(pNode.ID.String()))}, Vulnerability: &model.VulnerabilitySpec{NoVuln: ptrfrom.Bool(false)}})
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to get certifyVuln with error: %w", err)
	// 	}
	// 	for _, cVuln := range certVulns {
	// 		nodes = append(nodes, cVuln)
	// 	}
	// }

	return nodes, nil
}

func sbomQuery(hasSBOMID string) predicate.BillOfMaterials {
	predicates := []predicate.BillOfMaterials{
		optionalPredicate(ptrfrom.String(hasSBOMID), IDEQ),
	}

	predicates = append(predicates, billofmaterials.HasIncludedSoftwarePackagesWith(packageVersionVulnQuery()))

	return billofmaterials.And(predicates...)
}

func packageVersionVulnQuery() predicate.PackageVersion {
	vulnID, _ := uuid.Parse("110d9f78-db10-52ba-99e2-4f65cca5e6c1")
	rv := []predicate.PackageVersion{
		packageversion.HasVulnWith(certifyvuln.VulnerabilityIDNEQ(vulnID)),
	}

	return packageversion.And(rv...)
}

// getSBOMObjectWithIncludes is used recreate the hasSBOM object be eager loading the edges
func sbomObjectWithIncludes(q *ent.BillOfMaterialsQuery) *ent.BillOfMaterialsQuery {

	return q.
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {})
		}).
		WithArtifact()
	// WithIncludedSoftwarePackages(func(q *ent.PackageVersionQuery) {
	// 	q.WithName(func(q *ent.PackageNameQuery) {})
	// 	q.WithVuln(func(q *ent.CertifyVulnQuery) {
	// 		q.WithVulnerability(func(q *ent.VulnerabilityIDQuery) {
	// 			vulnerabilityid.VulnerabilityIDNEQ("110d9f78-db10-52ba-99e2-4f65cca5e6c1")
	// 		})
	// 	})
	// })
}
