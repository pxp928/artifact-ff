// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
)

// Artifact is the model entity for the Artifact schema.
type Artifact struct {
	config `json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// Algorithm holds the value of the "algorithm" field.
	Algorithm string `json:"algorithm,omitempty"`
	// Digest holds the value of the "digest" field.
	Digest string `json:"digest,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the ArtifactQuery when eager-loading is set.
	Edges        ArtifactEdges `json:"edges"`
	selectValues sql.SelectValues
}

// ArtifactEdges holds the relations/edges for other nodes in the graph.
type ArtifactEdges struct {
	// Occurrences holds the value of the occurrences edge.
	Occurrences []*Occurrence `json:"occurrences,omitempty"`
	// Sbom holds the value of the sbom edge.
	Sbom []*BillOfMaterials `json:"sbom,omitempty"`
	// Attestations holds the value of the attestations edge.
	Attestations []*SLSAAttestation `json:"attestations,omitempty"`
	// Same holds the value of the same edge.
	Same []*HashEqual `json:"same,omitempty"`
	// IncludedInSboms holds the value of the included_in_sboms edge.
	IncludedInSboms []*BillOfMaterials `json:"included_in_sboms,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [5]bool
	// totalCount holds the count of the edges above.
	totalCount [5]map[string]int

	namedOccurrences     map[string][]*Occurrence
	namedSbom            map[string][]*BillOfMaterials
	namedAttestations    map[string][]*SLSAAttestation
	namedSame            map[string][]*HashEqual
	namedIncludedInSboms map[string][]*BillOfMaterials
}

// OccurrencesOrErr returns the Occurrences value or an error if the edge
// was not loaded in eager-loading.
func (e ArtifactEdges) OccurrencesOrErr() ([]*Occurrence, error) {
	if e.loadedTypes[0] {
		return e.Occurrences, nil
	}
	return nil, &NotLoadedError{edge: "occurrences"}
}

// SbomOrErr returns the Sbom value or an error if the edge
// was not loaded in eager-loading.
func (e ArtifactEdges) SbomOrErr() ([]*BillOfMaterials, error) {
	if e.loadedTypes[1] {
		return e.Sbom, nil
	}
	return nil, &NotLoadedError{edge: "sbom"}
}

// AttestationsOrErr returns the Attestations value or an error if the edge
// was not loaded in eager-loading.
func (e ArtifactEdges) AttestationsOrErr() ([]*SLSAAttestation, error) {
	if e.loadedTypes[2] {
		return e.Attestations, nil
	}
	return nil, &NotLoadedError{edge: "attestations"}
}

// SameOrErr returns the Same value or an error if the edge
// was not loaded in eager-loading.
func (e ArtifactEdges) SameOrErr() ([]*HashEqual, error) {
	if e.loadedTypes[3] {
		return e.Same, nil
	}
	return nil, &NotLoadedError{edge: "same"}
}

// IncludedInSbomsOrErr returns the IncludedInSboms value or an error if the edge
// was not loaded in eager-loading.
func (e ArtifactEdges) IncludedInSbomsOrErr() ([]*BillOfMaterials, error) {
	if e.loadedTypes[4] {
		return e.IncludedInSboms, nil
	}
	return nil, &NotLoadedError{edge: "included_in_sboms"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Artifact) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case artifact.FieldAlgorithm, artifact.FieldDigest:
			values[i] = new(sql.NullString)
		case artifact.FieldID:
			values[i] = new(uuid.UUID)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Artifact fields.
func (a *Artifact) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case artifact.FieldID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				a.ID = *value
			}
		case artifact.FieldAlgorithm:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field algorithm", values[i])
			} else if value.Valid {
				a.Algorithm = value.String
			}
		case artifact.FieldDigest:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field digest", values[i])
			} else if value.Valid {
				a.Digest = value.String
			}
		default:
			a.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the Artifact.
// This includes values selected through modifiers, order, etc.
func (a *Artifact) Value(name string) (ent.Value, error) {
	return a.selectValues.Get(name)
}

// QueryOccurrences queries the "occurrences" edge of the Artifact entity.
func (a *Artifact) QueryOccurrences() *OccurrenceQuery {
	return NewArtifactClient(a.config).QueryOccurrences(a)
}

// QuerySbom queries the "sbom" edge of the Artifact entity.
func (a *Artifact) QuerySbom() *BillOfMaterialsQuery {
	return NewArtifactClient(a.config).QuerySbom(a)
}

// QueryAttestations queries the "attestations" edge of the Artifact entity.
func (a *Artifact) QueryAttestations() *SLSAAttestationQuery {
	return NewArtifactClient(a.config).QueryAttestations(a)
}

// QuerySame queries the "same" edge of the Artifact entity.
func (a *Artifact) QuerySame() *HashEqualQuery {
	return NewArtifactClient(a.config).QuerySame(a)
}

// QueryIncludedInSboms queries the "included_in_sboms" edge of the Artifact entity.
func (a *Artifact) QueryIncludedInSboms() *BillOfMaterialsQuery {
	return NewArtifactClient(a.config).QueryIncludedInSboms(a)
}

// Update returns a builder for updating this Artifact.
// Note that you need to call Artifact.Unwrap() before calling this method if this Artifact
// was returned from a transaction, and the transaction was committed or rolled back.
func (a *Artifact) Update() *ArtifactUpdateOne {
	return NewArtifactClient(a.config).UpdateOne(a)
}

// Unwrap unwraps the Artifact entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (a *Artifact) Unwrap() *Artifact {
	_tx, ok := a.config.driver.(*txDriver)
	if !ok {
		panic("ent: Artifact is not a transactional entity")
	}
	a.config.driver = _tx.drv
	return a
}

// String implements the fmt.Stringer.
func (a *Artifact) String() string {
	var builder strings.Builder
	builder.WriteString("Artifact(")
	builder.WriteString(fmt.Sprintf("id=%v, ", a.ID))
	builder.WriteString("algorithm=")
	builder.WriteString(a.Algorithm)
	builder.WriteString(", ")
	builder.WriteString("digest=")
	builder.WriteString(a.Digest)
	builder.WriteByte(')')
	return builder.String()
}

// NamedOccurrences returns the Occurrences named value or an error if the edge was not
// loaded in eager-loading with this name.
func (a *Artifact) NamedOccurrences(name string) ([]*Occurrence, error) {
	if a.Edges.namedOccurrences == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := a.Edges.namedOccurrences[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (a *Artifact) appendNamedOccurrences(name string, edges ...*Occurrence) {
	if a.Edges.namedOccurrences == nil {
		a.Edges.namedOccurrences = make(map[string][]*Occurrence)
	}
	if len(edges) == 0 {
		a.Edges.namedOccurrences[name] = []*Occurrence{}
	} else {
		a.Edges.namedOccurrences[name] = append(a.Edges.namedOccurrences[name], edges...)
	}
}

// NamedSbom returns the Sbom named value or an error if the edge was not
// loaded in eager-loading with this name.
func (a *Artifact) NamedSbom(name string) ([]*BillOfMaterials, error) {
	if a.Edges.namedSbom == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := a.Edges.namedSbom[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (a *Artifact) appendNamedSbom(name string, edges ...*BillOfMaterials) {
	if a.Edges.namedSbom == nil {
		a.Edges.namedSbom = make(map[string][]*BillOfMaterials)
	}
	if len(edges) == 0 {
		a.Edges.namedSbom[name] = []*BillOfMaterials{}
	} else {
		a.Edges.namedSbom[name] = append(a.Edges.namedSbom[name], edges...)
	}
}

// NamedAttestations returns the Attestations named value or an error if the edge was not
// loaded in eager-loading with this name.
func (a *Artifact) NamedAttestations(name string) ([]*SLSAAttestation, error) {
	if a.Edges.namedAttestations == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := a.Edges.namedAttestations[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (a *Artifact) appendNamedAttestations(name string, edges ...*SLSAAttestation) {
	if a.Edges.namedAttestations == nil {
		a.Edges.namedAttestations = make(map[string][]*SLSAAttestation)
	}
	if len(edges) == 0 {
		a.Edges.namedAttestations[name] = []*SLSAAttestation{}
	} else {
		a.Edges.namedAttestations[name] = append(a.Edges.namedAttestations[name], edges...)
	}
}

// NamedSame returns the Same named value or an error if the edge was not
// loaded in eager-loading with this name.
func (a *Artifact) NamedSame(name string) ([]*HashEqual, error) {
	if a.Edges.namedSame == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := a.Edges.namedSame[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (a *Artifact) appendNamedSame(name string, edges ...*HashEqual) {
	if a.Edges.namedSame == nil {
		a.Edges.namedSame = make(map[string][]*HashEqual)
	}
	if len(edges) == 0 {
		a.Edges.namedSame[name] = []*HashEqual{}
	} else {
		a.Edges.namedSame[name] = append(a.Edges.namedSame[name], edges...)
	}
}

// NamedIncludedInSboms returns the IncludedInSboms named value or an error if the edge was not
// loaded in eager-loading with this name.
func (a *Artifact) NamedIncludedInSboms(name string) ([]*BillOfMaterials, error) {
	if a.Edges.namedIncludedInSboms == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := a.Edges.namedIncludedInSboms[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (a *Artifact) appendNamedIncludedInSboms(name string, edges ...*BillOfMaterials) {
	if a.Edges.namedIncludedInSboms == nil {
		a.Edges.namedIncludedInSboms = make(map[string][]*BillOfMaterials)
	}
	if len(edges) == 0 {
		a.Edges.namedIncludedInSboms[name] = []*BillOfMaterials{}
	} else {
		a.Edges.namedIncludedInSboms[name] = append(a.Edges.namedIncludedInSboms[name], edges...)
	}
}

// Artifacts is a parsable slice of Artifact.
type Artifacts []*Artifact
