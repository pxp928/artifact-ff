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

// Query IsOccurrence

func (c *ageClient) IsOccurrence(ctx context.Context, isOccurrenceSpec *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {
	return nil, nil
}

// Ingest IngestOccurrences

func (c *ageClient) IngestOccurrences(ctx context.Context, subjects model.PackageOrSourceInputs, artifacts []*model.ArtifactInputSpec, occurrences []*model.IsOccurrenceInputSpec) ([]*model.IsOccurrence, error) {
	var modelIsOccurrences []*model.IsOccurrence

	for i := range occurrences {
		// var isOccurrence *model.IsOccurrence
		var err error
		if len(subjects.Packages) > 0 {
			subject := model.PackageOrSourceInput{Package: subjects.Packages[i]}
			_, err = c.IngestOccurrence(ctx, subject, *artifacts[i], *occurrences[i])
			if err != nil {
				return nil, gqlerror.Errorf("ingestOccurrence failed with err: %v", err)
			}
		}
		//modelIsOccurrences = append(modelIsOccurrences, isOccurrence)
	}
	return modelIsOccurrences, nil
}

// Ingest IngestOccurrence

func (c *ageClient) IngestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, artifact model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec) (*model.IsOccurrence, error) {

	if subject.Package != nil {
		// TODO: use generics here between PkgInputSpec and PkgSpecs?
		var namespace string
		if subject.Package.Namespace != nil {
			namespace = *subject.Package.Namespace
		} else {
			namespace = ""
		}
		var version string
		if subject.Package.Version != nil {
			version = *subject.Package.Version
		} else {
			version = ""
		}
		var subpath string
		if subject.Package.Subpath != nil {
			subpath = *subject.Package.Subpath
		} else {
			subpath = ""
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
MATCH (a:Artifact{algorithm:'%s',digest:'%s'})
MERGE (v1) <-[:subject]- (isOccurrence:IsOccurrence{justification:'%s',origin:'%s',collector:'%s'}) -[:has_occurrence]-> (a)
RETURN isOccurrence
`
		cursor, err := tx.ExecCypher(1, query, subject.Package.Type, namespace, subject.Package.Name, version, subpath, strings.ToLower(artifact.Algorithm), strings.ToLower(artifact.Digest),
			occurrence.Justification, occurrence.Origin, occurrence.Collector)
		if err != nil {
			return nil, err
		}

		count := 0
		for cursor.Next() {
			entities, err := cursor.GetRow()
			if err != nil {
				panic(err)
			}

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
	} else if subject.Source != nil {
		// // TODO: use generics here between SourceInputSpec and SourceSpec?
		// selectedSrcSpec := helper.ConvertSrcInputSpecToSrcSpec(subject.Source)

		// returnValue := " RETURN type.type, namespace.namespace, name.name, name.tag, name.commit, isOccurrence, objArt.algorithm, objArt.digest"

		// query := "MATCH (root:Src)-[:SrcHasType]->(type:SrcType)-[:SrcHasNamespace]->(namespace:SrcNamespace)" +
		// 	"-[:SrcHasName]->(name:SrcName), (objArt:Artifact)"

		// sb.WriteString(query)
		// setSrcMatchValues(&sb, selectedSrcSpec, false, &firstMatch, queryValues)
		// setArtifactMatchValues(&sb, occurrenceArt, true, &firstMatch, queryValues)

		// merge := "\nMERGE (name)<-[:subject]-(isOccurrence:IsOccurrence{justification:$justification,origin:$origin,collector:$collector})" +
		// 	"-[:has_occurrence]->(objArt)"
		// sb.WriteString(merge)
		// sb.WriteString(returnValue)

		// result, err := session.WriteTransaction(
		// 	func(tx neo4j.Transaction) (interface{}, error) {
		// 		result, err := tx.Run(sb.String(), queryValues)
		// 		if err != nil {
		// 			return nil, err
		// 		}

		// 		// query returns a single record
		// 		record, err := result.Single()
		// 		if err != nil {
		// 			return nil, err
		// 		}

		// 		tag := record.Values[3]
		// 		commit := record.Values[4]
		// 		nameStr := record.Values[2].(string)
		// 		namespaceStr := record.Values[1].(string)
		// 		srcType := record.Values[0].(string)
		// 		src := generateModelSource(srcType, namespaceStr, nameStr, commit, tag)

		// 		algorithm := record.Values[6].(string)
		// 		digest := record.Values[7].(string)
		// 		artifact := generateModelArtifact(algorithm, digest)

		// 		isOccurrenceNode := dbtype.Node{}
		// 		if record.Values[5] != nil {
		// 			isOccurrenceNode = record.Values[5].(dbtype.Node)
		// 		} else {
		// 			return nil, gqlerror.Errorf("isOccurrence Node not found in neo4j")
		// 		}

		// 		isOccurrence := generateModelIsOccurrence(src, artifact, isOccurrenceNode.Props[justification].(string),
		// 			isOccurrenceNode.Props[origin].(string), isOccurrenceNode.Props[collector].(string))

		// 		return isOccurrence, nil
		// 	})
		// if err != nil {
		// 	return nil, err
		// }

		// return result.(*model.IsOccurrence), nil

	} else {
		return nil, gqlerror.Errorf("package or source not specified for IngestOccurrence")
	}
	return nil, nil
}
