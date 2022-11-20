package certifier

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
)

type Certifier interface {
	CertifyVulns(ctx context.Context, rootComponent *Component, docChannel chan<- *processor.Document) error
}

// Emitter processes a document
type Emitter func(*processor.Document) error

// ErrHandler processes an error and returns a boolean representing if
// the error was able to be gracefully handled
type ErrHandler func(error) bool

// DocumentType describes the type of the document contents for schema checks
type CertfierType string

// Document* is the enumerables of DocumentType
const (
	CertifierOSV CertfierType = "OSV"
)

type Component struct {
	CurPackage  assembler.PackageNode
	DepPackages []*Component
}
