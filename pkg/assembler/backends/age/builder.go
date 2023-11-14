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

func (c *ageClient) Builders(ctx context.Context, builderSpec *model.BuilderSpec) ([]*model.Builder, error) {
	return nil, nil
}

func (c *ageClient) IngestBuilders(ctx context.Context, builders []*model.BuilderInputSpec) ([]*model.Builder, error) {
	var modelBuilders []*model.Builder
	for _, build := range builders {
		_, err := c.IngestBuilder(ctx, build)
		if err != nil {
			return nil, gqlerror.Errorf("IngestBuilder failed with err: %v", err)
		}
		//modelBuilders = append(modelBuilders, modelBuild)
	}
	return modelBuilders, nil
}

func (c *ageClient) IngestBuilder(ctx context.Context, builder *model.BuilderInputSpec) (*model.Builder, error) {

	tx, err := c.ag.Begin()
	if err != nil {
		panic(err)
	}

	query := "MERGE (b:Builder{uri:'%s'}) RETURN b"
	cursor, err := tx.ExecCypher(1, query, builder.URI)
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

func generateModelBuilder(uri string) *model.Builder {
	builder := model.Builder{
		URI: uri,
	}
	return &builder
}
