package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/graphdb"
	attestation_osv "github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/certifier/osv_query"
	"github.com/guacsec/guac/pkg/handler/processor"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j/dbtype"
	osv_scanner "golang.org/x/vuln/osv"
)

const (
	CertifierOSV = "OSV"
)

type OSVCertifier struct{}

func (o *OSVCertifier) CertifyVulns(ctx context.Context, client graphdb.Client, docChannel chan<- *processor.Document) error {
	var packNodes []assembler.PackageNode
	results, err := graphdb.ReadQueryForTesting(client, "MATCH (n:Package) RETURN n", nil)
	if err != nil {
		return err
	}
	for _, result := range results {
		foundNode := result.(dbtype.Node)
		foundPack := assembler.PackageNode{}
		foundPack.Purl = foundNode.Props["purl"].(string)
		packNodes = append(packNodes, foundPack)
	}

	err = getVulnerabilities(packNodes, docChannel)
	if err != nil {
		return err
	}
	return nil
}

func (o *OSVCertifier) Type() string {
	return CertifierOSV
}

func getVulnerabilities(packNodes []assembler.PackageNode, docChannel chan<- *processor.Document) error {
	var query osv_query.BatchedQuery
	for _, pack := range packNodes {
		purlQuery := osv_query.MakePURLRequest(pack.Purl)
		purlQuery.Package.PURL = pack.Purl
		purlQuery.Package.Digest = pack.Digest
		query.Queries = append(query.Queries, purlQuery)
	}

	resp, err := osv_query.MakeRequest(query)
	if err != nil {
		return fmt.Errorf("scan failed: %v", err)
	}

	for i, query := range query.Queries {
		response := resp.Results[i]
		doc, err := generateDocument(*query, response.Vulns)
		if err != nil {
			return err
		}
		docChannel <- doc
	}
	return nil
}

func generateDocument(query osv_query.Query, vulns []osv_scanner.Entry) (*processor.Document, error) {
	payload, err := parseOSVCertifyPredicate(createAttestation(query, vulns))
	if err != nil {
		return nil, err
	}
	doc := &processor.Document{
		Blob:   payload,
		Type:   processor.DocumentITE6OSV,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "guac",
			Source:    "guac",
		},
	}
	return doc, nil
}

func createAttestation(query osv_query.Query, vulns []osv_scanner.Entry) *attestation_osv.AssertionStatement {
	currentTime := time.Now()
	var subjects []intoto.Subject
	var attribute attestation_osv.Attribute

	attestation := &attestation_osv.AssertionStatement{}
	attestation.StatementHeader.Type = "https://in-toto.io/Statement/v0.1"
	attestation.StatementHeader.PredicateType = "http://in-toto.io/attestation/scai/attribute-assertion/v0.1"
	if len(query.Package.Digest) > 0 {
		for _, digest := range query.Package.Digest {
			digestSplit := strings.Split(digest, ":")
			subjects = append(subjects, intoto.Subject{
				Name: query.Package.PURL,
				Digest: slsa.DigestSet{
					digestSplit[0]: digest,
				},
			})
		}
	} else {
		subjects = append(subjects, intoto.Subject{
			Name: query.Package.PURL,
		})
	}

	attestation.StatementHeader.Subject = subjects
	attestation.Predicate.Producer.Type = "guac"
	attestation.Predicate.Producer.Id = "guecsec/guac"
	attribute.Attribute = "scanned"
	attribute.Evidence.Scanner.Id = "osv.dev"
	attribute.Evidence.Scanner.Type = "osv"
	attribute.Evidence.Date = &currentTime

	attestation.Predicate.Attributes = append(attestation.Predicate.Attributes, attribute)

	for _, vuln := range vulns {

		attestation.Predicate.Attributes[0].Evidence.Results = append(attestation.Predicate.Attributes[0].Evidence.Results, attestation_osv.Result{
			OSVID: vuln.ID,
		})
	}
	return attestation
}

func parseOSVCertifyPredicate(p *attestation_osv.AssertionStatement) ([]byte, error) {
	blob, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return blob, nil
}
