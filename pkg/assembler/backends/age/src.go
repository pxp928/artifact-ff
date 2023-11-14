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

func (c *ageClient) Sources(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {
	return nil, nil
}

func (c *ageClient) IngestSources(ctx context.Context, sources []*model.SourceInputSpec) ([]*model.Source, error) {
	var modelSources []*model.Source
	for _, src := range sources {
		modelSrc, err := c.IngestSource(ctx, *src)
		if err != nil {
			return nil, gqlerror.Errorf("IngestSources failed with err: %v", err)
		}
		modelSources = append(modelSources, modelSrc)
	}
	return modelSources, nil
}

func (c *ageClient) IngestSource(ctx context.Context, source model.SourceInputSpec) (*model.Source, error) {
	if source.Commit != nil && source.Tag != nil {
		if *source.Commit != "" && *source.Tag != "" {
			return nil, gqlerror.Errorf("Passing both commit and tag selectors is an error")
		}
	}

	var commit string
	if source.Commit != nil {
		commit = *source.Commit
	} else {
		commit = ""
	}

	var tag string
	if source.Tag != nil {
		tag = *source.Tag
	} else {
		tag = ""
	}

	tx, err := c.ag.Begin()
	if err != nil {
		panic(err)
	}

	query := "MERGE (root:Src) \nMERGE (root) -[:SrcHasType]-> (type:SrcType{type:'%s'}) \nMERGE (type) -[:SrcHasNamespace]-> (ns:SrcNamespace{namespace:'%s'}) \nMERGE (ns) -[:SrcHasName]-> (name:SrcName{name:'%s',commit:'%s',tag:'%s'}) \nRETURN type, ns, name"
	cursor, err := tx.ExecCypher(3, query, source.Type, source.Namespace, source.Name, commit, tag)
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
