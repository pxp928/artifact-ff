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
	"strings"

	"github.com/apache/age/drivers/golang/age"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (c *ageClient) Artifacts(ctx context.Context, artifactSpec *model.ArtifactSpec) ([]*model.Artifact, error) {
	return nil, nil
}

func (c *ageClient) IngestArtifacts(ctx context.Context, artifacts []*model.ArtifactInputSpec) ([]*model.Artifact, error) {
	var modelArtifacts []*model.Artifact
	for _, art := range artifacts {
		_, err := c.IngestArtifact(ctx, art)
		if err != nil {
			return nil, gqlerror.Errorf("ingestArtifact failed with err: %v", err)
		}
		//modelArtifacts = append(modelArtifacts, modelArt)
	}
	return modelArtifacts, nil
}

func (c *ageClient) IngestArtifact(ctx context.Context, artifact *model.ArtifactInputSpec) (*model.Artifact, error) {
	tx, err := c.ag.Begin()
	if err != nil {
		panic(err)
	}

	query := "MERGE (a:Artifact{algorithm:'%s',digest:'%s'}) \nRETURN a"
	cursor, err := tx.ExecCypher(1, query, strings.ToLower(artifact.Algorithm), strings.ToLower(artifact.Digest))
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

// func setArtifactMatchValues(sb *strings.Builder, art *model.ArtifactSpec, objectArt bool, firstMatch *bool, queryValues map[string]any) {
// 	if art != nil {
// 		if art.Algorithm != nil {
// 			if !objectArt {
// 				matchProperties(sb, *firstMatch, "a", "algorithm", "$algorithm")
// 				queryValues["algorithm"] = strings.ToLower(*art.Algorithm)
// 			} else {
// 				matchProperties(sb, *firstMatch, "objArt", "algorithm", "$objAlgorithm")
// 				queryValues["objAlgorithm"] = strings.ToLower(*art.Algorithm)
// 			}
// 			*firstMatch = false
// 		}

// 		if art.Digest != nil {
// 			if !objectArt {
// 				matchProperties(sb, *firstMatch, "a", "digest", "$digest")
// 				queryValues["digest"] = strings.ToLower(*art.Digest)
// 			} else {
// 				matchProperties(sb, *firstMatch, "objArt", "digest", "$objDigest")
// 				queryValues["objDigest"] = strings.ToLower(*art.Digest)
// 			}
// 			*firstMatch = false
// 		}
// 	}
// }

// func generateModelArtifact(algorithm, digest string) *model.Artifact {
// 	artifact := model.Artifact{
// 		Algorithm: algorithm,
// 		Digest:    digest,
// 	}
// 	return &artifact
// }
