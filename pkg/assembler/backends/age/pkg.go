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

func (c *ageClient) Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	return nil, nil
}
func (c *ageClient) IngestPackages(ctx context.Context, pkgs []*model.PkgInputSpec) ([]*model.Package, error) {
	var modelPkgs []*model.Package
	for _, pkg := range pkgs {
		_, err := c.IngestPackage(ctx, *pkg)
		if err != nil {
			return nil, gqlerror.Errorf("ingestPackage failed with err: %v", err)
		}
		//modelPkgs = append(modelPkgs, modelPkg)
	}
	return modelPkgs, nil
}

func (c *ageClient) IngestPackage(ctx context.Context, pkg model.PkgInputSpec) (*model.Package, error) {
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

	tx, err := c.ag.Begin()
	if err != nil {
		panic(err)
	}

	//query := "MERGE (root:Pkg) MERGE (root) -[:PkgHasType]-> (type:PkgType{type:'%s'}) MERGE (type) -[:PkgHasNamespace]-> (ns:PkgNamespace{namespace:'%s'}) MERGE (ns) -[:PkgHasName]-> (name:PkgName{name:'%s'}) MERGE (name) -[:PkgHasVersion]-> (version:PkgVersion{version:'%s',subpath:'%s'}) RETURN type.type, ns.namespace, name.name, version.version, version.subpath"
	query := "MERGE (root:Pkg) \nMERGE (root) -[:PkgHasType]-> (type:PkgType{type:'%s'}) \nMERGE (type) -[:PkgHasNamespace]-> (ns:PkgNamespace{namespace:'%s'}) \nMERGE (ns) -[:PkgHasName]-> (name:PkgName{name:'%s'}) \nMERGE (name) -[:PkgHasVersion]-> (version:PkgVersion{version:'%s',subpath:'%s'}) \nRETURN type, ns, name, version"
	cursor, err := tx.ExecCypher(4, query, pkg.Type, namespace, pkg.Name, version, subpath)
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

	return nil, nil
}
