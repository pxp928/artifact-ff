package certify

import (
	"context"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/graphdb"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/osv"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j/dbtype"
)

const (
	BufferChannelSize int = 1000
)

func init() {
	_ = RegisterCertifier(osv.NewOSVCertificationParser, certifier.CertifierOSV)
}

var (
	documentCertifier = map[certifier.CertfierType]func() certifier.Certifier{}
)

func RegisterCertifier(c func() certifier.Certifier, certifierType certifier.CertfierType) error {
	if _, ok := documentCertifier[certifierType]; ok {
		return fmt.Errorf("the certifier is being overwritten: %s", certifierType)
	}
	documentCertifier[certifierType] = c

	return nil
}

func Certify(ctx context.Context, client graphdb.Client, emitter certifier.Emitter, handleErr certifier.ErrHandler) error {

	// docChan to collect artifacts
	compChan := make(chan *certifier.Component, BufferChannelSize)
	// errChan to receive error from collectors
	errChan := make(chan error, 1)
	// logger
	logger := logging.FromContext(ctx)

	go func() {
		errChan <- getComponents(ctx, client, compChan)
	}()

	componentsCaptured := false
	for componentsCaptured != true {
		select {
		case d := <-compChan:
			if err := generateDocuments(ctx, d, emitter, handleErr); err != nil {
				logger.Errorf("generate certifier documents error: %v", err)
			}
		case err := <-errChan:
			if !handleErr(err) {
				return err
			}
			componentsCaptured = true
		}
	}
	for len(compChan) > 0 {
		d := <-compChan
		if err := generateDocuments(ctx, d, emitter, handleErr); err != nil {
			logger.Errorf("generate certifier documents error: %v", err)
		}
	}

	return nil
}

func generateDocuments(ctx context.Context, collectedComponent *certifier.Component, emitter certifier.Emitter, handleErr certifier.ErrHandler) error {

	// docChan to collect artifacts
	docChan := make(chan *processor.Document, BufferChannelSize)
	// errChan to receive error from collectors
	errChan := make(chan error, len(documentCertifier))
	// logger
	logger := logging.FromContext(ctx)

	for _, certifier := range documentCertifier {
		c := certifier()
		go func() {

			errChan <- c.CertifyVulns(ctx, collectedComponent, docChan)
		}()
	}

	numCertifiers := len(documentCertifier)
	certifiersDone := 0
	for certifiersDone < numCertifiers {
		select {
		case d := <-docChan:
			if err := emitter(d); err != nil {
				logger.Errorf("emit error: %v", err)
			}
		case err := <-errChan:
			if !handleErr(err) {
				return err
			}
			certifiersDone += 1
		}
	}
	for len(docChan) > 0 {
		d := <-docChan
		if err := emitter(d); err != nil {
			logger.Errorf("emit error: %v", err)
		}
	}
	return nil
}

func getComponents(ctx context.Context, client graphdb.Client, compChan chan<- *certifier.Component) error {
	// Get top level package MATCH (p:Package) WHERE NOT (p)<-[:DependsOn]-() return p
	// Get all packages that the top level package depends on MATCH (p:Package) WHERE NOT (p)<-[:DependsOn]-() WITH p MATCH (p)-[:DependsOn]->(p2:Package) return p2
	// MATCH (p:Package) WHERE p.purl = "pkg:oci/vul-image-latest?repository_url=ppatel1989" WITH p MATCH (p)-[:DependsOn]->(p2:Package) return p2

	// TODO: How to handle if a package already has been scanned? Rescan and just merge the nodes...

	roots, err := graphdb.ReadQueryForTesting(client, "MATCH (p:Package) WHERE NOT (p)<-[:DependsOn]-() return p", nil)
	if err != nil {
		return err
	}
	for _, result := range roots {
		foundNode := result.(dbtype.Node)
		rootPackage := assembler.PackageNode{}
		rootPackage.Purl = foundNode.Props["purl"].(string)
		deps, err := getCompHelper(ctx, client, rootPackage.Purl)
		if err != nil {
			return err
		}
		rootComponent := &certifier.Component{
			CurPackage:  rootPackage,
			DepPackages: deps,
		}
		compChan <- rootComponent
	}
	return nil
}

func getCompHelper(ctx context.Context, client graphdb.Client, parentPurl string) ([]*certifier.Component, error) {
	dependencies, err := graphdb.ReadQueryForTesting(client, "MATCH (p:Package) WHERE p.purl = $rootPurl WITH p MATCH (p)-[:DependsOn]->(p2:Package) return p2",
		map[string]any{"rootPurl": parentPurl})
	if err != nil {
		return nil, err
	}
	depPackages := []*certifier.Component{}
	for _, dep := range dependencies {
		foundDep := dep.(dbtype.Node)
		foundDepPack := assembler.PackageNode{}
		foundDepPack.Purl = foundDep.Props["purl"].(string)
		deps, err := getCompHelper(ctx, client, foundDepPack.Purl)
		if err != nil {
			return nil, err
		}
		depPackages = append(depPackages, &certifier.Component{
			CurPackage:  foundDepPack,
			DepPackages: deps,
		})
	}
	return depPackages, nil
}
