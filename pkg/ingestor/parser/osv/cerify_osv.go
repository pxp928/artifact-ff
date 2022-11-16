//
// Copyright 2022 The GUAC Authors.
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

package certify_osv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/guacsec/guac/pkg/assembler"
	attestation_osv "github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

const (
	algorithmSHA256 string = "sha256"
	attestationType string = "CERTIFY_OSV"
)

type osvCertificationParser struct {
	doc         *processor.Document
	packageNode []assembler.PackageNode
	attestation assembler.AttestationNode
	vulns       []assembler.VulnerabilityNode
}

// NewCerifyParser initializes the cerifyParser
func NewOSVCertificationParser() common.DocumentParser {
	return &osvCertificationParser{
		packageNode: []assembler.PackageNode{},
		attestation: assembler.AttestationNode{},
		vulns:       []assembler.VulnerabilityNode{},
	}
}

// Parse breaks out the document into the graph components
func (c *osvCertificationParser) Parse(ctx context.Context, doc *processor.Document) error {
	c.doc = doc
	statement, err := parseOSVCertifyPredicate(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse slsa predicate: %w", err)
	}
	c.getSubject(statement)
	c.getAttestation(doc.Blob, doc.SourceInformation.Source, statement)
	c.getVulns(doc.Blob, doc.SourceInformation.Source, statement)
	return nil
}

func (c *osvCertificationParser) getSubject(statement *attestation_osv.AssertionStatement) {
	currentPackage := assembler.PackageNode{}
	for _, sub := range statement.Subject {
		currentPackage.Purl = sub.Name
		if len(sub.Digest) > 0 {
			for alg, ds := range sub.Digest {
				currentPackage.Digest = append(currentPackage.Digest, strings.ToLower(alg+":"+strings.Trim(ds, "'")))
			}
		}
		c.packageNode = append(c.packageNode, currentPackage)
	}
}

func (c *osvCertificationParser) getAttestation(blob []byte, source string, statement *attestation_osv.AssertionStatement) {
	h := sha256.Sum256(blob)
	attNode := assembler.AttestationNode{
		FilePath:        source,
		Digest:          algorithmSHA256 + ":" + hex.EncodeToString(h[:]),
		AttestationType: attestationType,
		Payload:         map[string]interface{}{},
		NodeData:        *assembler.NewObjectMetadata(c.doc.SourceInformation),
	}
	attNode.Payload["producer_id"] = statement.Predicate.Producer.Id
	attNode.Payload["producer_type"] = statement.Predicate.Producer.Type
	attNode.Payload["attribute"] = statement.Predicate.Attributes[0].Attribute
	attNode.Payload["scanner_id"] = statement.Predicate.Attributes[0].Evidence.Scanner.Id
	attNode.Payload["scanner_type"] = statement.Predicate.Attributes[0].Evidence.Scanner.Type
	attNode.Payload["scannedOn"] = statement.Predicate.Attributes[0].Evidence.ScannedOn.String()
	for i, id := range statement.Predicate.Attributes[0].Evidence.Results {
		attNode.Payload["osv_id_"+strconv.Itoa(i)] = id.OSVID
	}
	c.attestation = attNode
}

func (c *osvCertificationParser) getVulns(blob []byte, source string, statement *attestation_osv.AssertionStatement) {
	for _, id := range statement.Predicate.Attributes[0].Evidence.Results {
		vulNode := assembler.VulnerabilityNode{}
		vulNode.ID = id.OSVID
		vulNode.NodeData = *assembler.NewObjectMetadata(c.doc.SourceInformation)
		c.vulns = append(c.vulns, vulNode)
	}
}

func parseOSVCertifyPredicate(p []byte) (*attestation_osv.AssertionStatement, error) {
	predicate := attestation_osv.AssertionStatement{}
	if err := json.Unmarshal(p, &predicate); err != nil {
		return nil, err
	}
	return &predicate, nil
}

// CreateNodes creates the GuacNode for the graph inputs
func (c *osvCertificationParser) CreateNodes(ctx context.Context) []assembler.GuacNode {
	nodes := []assembler.GuacNode{}
	for _, pack := range c.packageNode {
		nodes = append(nodes, pack)
	}
	for _, vuln := range c.vulns {
		nodes = append(nodes, vuln)
	}
	nodes = append(nodes, c.attestation)
	return nodes
}

// CreateEdges creates the GuacEdges that form the relationship for the graph inputs
func (c *osvCertificationParser) CreateEdges(ctx context.Context, foundIdentities []assembler.IdentityNode) []assembler.GuacEdge {
	edges := []assembler.GuacEdge{}
	for _, i := range foundIdentities {
		edges = append(edges, assembler.IdentityForEdge{IdentityNode: i, AttestationNode: c.attestation})
	}
	for _, pack := range c.packageNode {
		edges = append(edges, assembler.AttestationForPackage{AttestationNode: c.attestation, PackageNode: pack})
	}
	for _, vuln := range c.vulns {
		edges = append(edges, assembler.VulnerableEdge{VulnNode: vuln, AtteNodes: c.attestation})
	}
	return edges
}

// GetIdentities gets the identity node from the document if they exist
func (c *osvCertificationParser) GetIdentities(ctx context.Context) []assembler.IdentityNode {
	return nil
}
