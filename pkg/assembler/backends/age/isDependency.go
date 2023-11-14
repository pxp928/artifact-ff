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
	"fmt"

	"github.com/apache/age/drivers/golang/age"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

const (
	versionRange   string = "versionRange"
	dependencyType string = "dependencyType"
)

// Query IsDependency

func (c *ageClient) IsDependency(ctx context.Context, isDependencySpec *model.IsDependencySpec) ([]*model.IsDependency, error) {
	return nil, nil
}

// Ingest IngestDependencies

func (c *ageClient) IngestDependencies(ctx context.Context, pkgs []*model.PkgInputSpec, depPkgs []*model.PkgInputSpec, depPkgMatchType model.MatchFlags, dependencies []*model.IsDependencyInputSpec) ([]*model.IsDependency, error) {
	var modelIsDependencies []*model.IsDependency
	for i := range dependencies {
		_, err := c.IngestDependency(ctx, *pkgs[i], *depPkgs[i], depPkgMatchType, *dependencies[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestDependency failed with err: %v", err)
		}
		//modelIsDependencies = append(modelIsDependencies, isDependency)
	}
	return modelIsDependencies, nil
}

// Ingest IsDependency

func (c *ageClient) IngestDependency(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, depPkgMatchType model.MatchFlags, dependency model.IsDependencyInputSpec) (*model.IsDependency, error) {
	var namespace string
	if pkg.Namespace != nil {
		namespace = *pkg.Namespace
	} else {
		namespace = ""
	}
	var version string
	if pkg.Version != nil {
		version = *pkg.Version
	} else {
		version = ""
	}
	var subpath string
	if pkg.Subpath != nil {
		subpath = *pkg.Subpath
	} else {
		subpath = ""
	}

	var depNamespace string
	if depPkg.Namespace != nil {
		depNamespace = *depPkg.Namespace
	} else {
		depNamespace = ""
	}
	var depVersion string
	if depPkg.Version != nil {
		depVersion = *depPkg.Version
	} else {
		depVersion = ""
	}
	var depSubpath string
	if depPkg.Subpath != nil {
		depSubpath = *depPkg.Subpath
	} else {
		depSubpath = ""
	}

	tx, err := c.ag.Begin()
	if err != nil {
		panic(err)
	}

	query := `
MATCH (root:Pkg)
MATCH (root) -[:PkgHasType]-> (:PkgType {type:'%s'})
             -[:PkgHasNamespace]-> (:PkgNamespace {namespace:'%s'})
             -[:PkgHasName]-> (:PkgName {name: '%s'})
             -[:PkgHasVersion]-> (v1:PkgVersion {version:'%s',subpath:'%s'})
MATCH (root) -[:PkgHasType]-> (:PkgType {type:'%s'})
             -[:PkgHasNamespace]-> (:PkgNamespace {namespace:'%s'})
             -[:PkgHasName]-> (:PkgName {name:'%s'})
             -[:PkgHasVersion]-> (v2:PkgVersion {version:'%s',subpath:'%s'})
MERGE (v1) <-[:subject]- (isDependency:IsDependency{versionRange:'%s',dependencyType:'%s',justification:'%s',origin:'%s',collector:'%s'}) -[:Dependency]-> (v2)
RETURN isDependency
`
	cursor, err := tx.ExecCypher(1, query, pkg.Type, namespace, pkg.Name, version, subpath, depPkg.Type, depNamespace, depPkg.Name, depVersion, depSubpath,
		dependency.VersionRange, dependency.DependencyType.String(), dependency.Justification, dependency.Origin, dependency.Collector)
	if err != nil {
		return nil, err
	}

	count := 0
	for cursor.Next() {
		entities, err := cursor.GetRow()
		if err != nil {
			panic(err)
		}
		// count++

		// path := entities[0].(*age.Path)

		// vertexStart := path.GetAsVertex(0)
		// edge := path.GetAsEdge(1)
		// vertexEnd := path.GetAsVertex(2)

		// fmt.Println(count, "]", vertexStart, edge.Props(), vertexEnd)

		count++
		for _, entity := range entities {
			vertex := entity.(*age.Vertex)
			fmt.Println(count, "]", vertex.Id(), vertex.Label(), vertex.Props())
		}
	}

	err = tx.Commit()
	if err != nil {
		return nil, err
	}

	// // query returns a single record
	// record, err := result.Single()
	// if err != nil {
	// 	return nil, err
	// }

	// qualifiersList := record.Values[5]
	// subPath := record.Values[4]
	// version := record.Values[3]
	// nameStr := record.Values[2].(string)
	// namespaceStr := record.Values[1].(string)
	// pkgType := record.Values[0].(string)

	// pkg := generateModelPackage(pkgType, namespaceStr, nameStr, version, subPath, qualifiersList)
	// return pkg, nil

	// return result.(*model.Package), nil
	return nil, nil
}

func convertDependencyTypeToEnum(status string) (model.DependencyType, error) {
	if status == model.DependencyTypeDirect.String() {
		return model.DependencyTypeDirect, nil
	}
	if status == model.DependencyTypeIndirect.String() {
		return model.DependencyTypeIndirect, nil
	}
	if status == model.DependencyTypeUnknown.String() {
		return model.DependencyTypeUnknown, nil
	}
	return model.DependencyTypeUnknown, fmt.Errorf("failed to convert DependencyType to enum")
}
