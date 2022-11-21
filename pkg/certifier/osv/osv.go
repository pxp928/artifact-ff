package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/certifier"
	attestation_osv "github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/certifier/osv_query"
	"github.com/guacsec/guac/pkg/handler/processor"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	osv_scanner "golang.org/x/vuln/osv"
)

type OSVCertifier struct {
	rootComponents *certifier.Component
}

// NewOSVCertificationParser initializes the OSVCertifier
func NewOSVCertificationParser() certifier.Certifier {
	return &OSVCertifier{
		rootComponents: nil,
	}
}

func (o *OSVCertifier) CertifyVulns(ctx context.Context, rootComponent *certifier.Component, docChannel chan<- *processor.Document) error {
	o.rootComponents = rootComponent
	_, err := o.certifyHelper(ctx, rootComponent, rootComponent.DepPackages, docChannel)
	if err != nil {
		return err
	}
	return nil
}

func (o *OSVCertifier) certifyHelper(ctx context.Context, topLevel *certifier.Component, depPackages []*certifier.Component, docChannel chan<- *processor.Document) ([]osv_scanner.Entry, error) {
	packNodes := []assembler.PackageNode{}
	totalDepVul := []osv_scanner.Entry{}
	for _, depPack := range depPackages {
		if len(depPack.DepPackages) > 0 {
			depVulns, err := o.certifyHelper(ctx, depPack, depPack.DepPackages, docChannel)
			if err != nil {
				return nil, nil
			}
			totalDepVul = append(totalDepVul, depVulns...)
		}
		packNodes = append(packNodes, depPack.CurPackage)
	}

	i := 0
	for i < len(packNodes) {
		query, lastIndex := getQuery(i, packNodes)
		vulns, err := getVulnerabilities(query, docChannel)
		if err != nil {
			return nil, err
		}
		i = lastIndex
		totalDepVul = append(totalDepVul, vulns...)
	}

	doc, err := generateDocument(topLevel.CurPackage.Purl, topLevel.CurPackage.Digest, totalDepVul)
	if err != nil {
		return nil, err
	}
	docChannel <- doc
	return totalDepVul, nil
}

func getQuery(lastIndex int, packNodes []assembler.PackageNode) (osv_query.BatchedQuery, int) {
	var query osv_query.BatchedQuery
	var stoppedIndex int
	j := 1
	for i := lastIndex; i < len(packNodes); i++ {
		purlQuery := osv_query.MakePURLRequest(packNodes[i].Purl)
		purlQuery.Package.PURL = packNodes[i].Purl
		purlQuery.Package.Digest = packNodes[i].Digest
		query.Queries = append(query.Queries, purlQuery)
		j++
		if j == 1000 {
			stoppedIndex = i
			return query, stoppedIndex
		}
	}
	stoppedIndex = len(packNodes)
	return query, stoppedIndex
}

func getVulnerabilities(query osv_query.BatchedQuery, docChannel chan<- *processor.Document) ([]osv_scanner.Entry, error) {

	resp, err := osv_query.MakeRequest(query)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %v", err)
	}
	totalDepVul := []osv_scanner.Entry{}
	for i, query := range query.Queries {
		response := resp.Results[i]
		totalDepVul = append(totalDepVul, response.Vulns...)
		doc, err := generateDocument(query.Package.PURL, query.Package.Digest, response.Vulns)
		if err != nil {
			return nil, err
		}
		docChannel <- doc
	}
	return totalDepVul, nil
}

func generateDocument(purl string, digest []string, vulns []osv_scanner.Entry) (*processor.Document, error) {
	payload, err := parseOSVCertifyPredicate(createAttestation(purl, digest, vulns))
	if err != nil {
		return nil, err
	}
	doc := &processor.Document{
		Blob:   payload,
		Type:   processor.DocumentITE6Vul,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "guac",
			Source:    "guac",
		},
	}
	return doc, nil
}

func createAttestation(purl string, digest []string, vulns []osv_scanner.Entry) *attestation_osv.AssertionStatement {
	currentTime := time.Now()
	var subjects []intoto.Subject

	attestation := &attestation_osv.AssertionStatement{}
	attestation.StatementHeader.Type = "https://in-toto.io/Statement/v0.1"
	attestation.StatementHeader.PredicateType = "https://in-toto.io/attestation/vuln/v0.1"
	if len(digest) > 0 {
		for _, digest := range digest {
			digestSplit := strings.Split(digest, ":")
			subjects = append(subjects, intoto.Subject{
				Name: purl,
				Digest: slsa.DigestSet{
					digestSplit[0]: digestSplit[1],
				},
			})
		}
	} else {
		subjects = append(subjects, intoto.Subject{
			Name: purl,
		})
	}

	attestation.StatementHeader.Subject = subjects
	attestation.Predicate.Invocation.Uri = "guac"
	attestation.Predicate.Invocation.ProducerID = "guecsec/guac"
	attestation.Predicate.Scanner.Uri = "osv.dev"
	attestation.Predicate.Scanner.Version = "0.0.14"
	attestation.Predicate.Metadata.ScannedOn = &currentTime

	for _, vuln := range vulns {

		attestation.Predicate.Scanner.Result = append(attestation.Predicate.Scanner.Result, attestation_osv.Result{
			VulnerabilityId: vuln.ID,
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
