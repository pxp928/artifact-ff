package certify

import (
	"context"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/graphdb"
	"github.com/guacsec/guac/pkg/certifier/osv"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

const (
	BufferChannelSize int = 1000
)

var (
	documentCertifier = map[string]Certifier{}
)

func init() {
	_ = RegisterCertifier(&osv.OSVCertifier{}, osv.CertifierOSV)
}

type Certifier interface {
	CertifyVulns(ctx context.Context, client graphdb.Client, docChannel chan<- *processor.Document) error
	// Type returns the Certifier type
	Type() string
}

// Emitter processes a document
type Emitter func(*processor.Document) error

// ErrHandler processes an error and returns a boolean representing if
// the error was able to be gracefully handled
type ErrHandler func(error) bool

func RegisterCertifier(c Certifier, certifierType string) error {
	if _, ok := documentCertifier[certifierType]; ok {
		return fmt.Errorf("the certifier is being overwritten: %s", certifierType)
	}
	documentCertifier[certifierType] = c

	return nil
}

func Certify(ctx context.Context, client graphdb.Client, emitter Emitter, handleErr ErrHandler) error {
	// docChan to collect artifacts
	docChan := make(chan *processor.Document, BufferChannelSize)
	// errChan to receive error from collectors
	errChan := make(chan error, len(documentCertifier))
	// logger
	logger := logging.FromContext(ctx)

	for _, certifier := range documentCertifier {
		c := certifier
		go func() {
			errChan <- c.CertifyVulns(ctx, client, docChan)
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
