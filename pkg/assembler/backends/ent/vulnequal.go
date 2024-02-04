// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnequal"
)

// VulnEqual is the model entity for the VulnEqual schema.
type VulnEqual struct {
	config `json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// Justification holds the value of the "justification" field.
	Justification string `json:"justification,omitempty"`
	// Origin holds the value of the "origin" field.
	Origin string `json:"origin,omitempty"`
	// Collector holds the value of the "collector" field.
	Collector string `json:"collector,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the VulnEqualQuery when eager-loading is set.
	Edges        VulnEqualEdges `json:"edges"`
	selectValues sql.SelectValues
}

// VulnEqualEdges holds the relations/edges for other nodes in the graph.
type VulnEqualEdges struct {
	// VulnerabilityIds holds the value of the vulnerability_ids edge.
	VulnerabilityIds []*VulnerabilityID `json:"vulnerability_ids,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
	// totalCount holds the count of the edges above.
	totalCount [1]map[string]int

	namedVulnerabilityIds map[string][]*VulnerabilityID
}

// VulnerabilityIdsOrErr returns the VulnerabilityIds value or an error if the edge
// was not loaded in eager-loading.
func (e VulnEqualEdges) VulnerabilityIdsOrErr() ([]*VulnerabilityID, error) {
	if e.loadedTypes[0] {
		return e.VulnerabilityIds, nil
	}
	return nil, &NotLoadedError{edge: "vulnerability_ids"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*VulnEqual) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case vulnequal.FieldJustification, vulnequal.FieldOrigin, vulnequal.FieldCollector:
			values[i] = new(sql.NullString)
		case vulnequal.FieldID:
			values[i] = new(uuid.UUID)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the VulnEqual fields.
func (ve *VulnEqual) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case vulnequal.FieldID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				ve.ID = *value
			}
		case vulnequal.FieldJustification:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field justification", values[i])
			} else if value.Valid {
				ve.Justification = value.String
			}
		case vulnequal.FieldOrigin:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field origin", values[i])
			} else if value.Valid {
				ve.Origin = value.String
			}
		case vulnequal.FieldCollector:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field collector", values[i])
			} else if value.Valid {
				ve.Collector = value.String
			}
		default:
			ve.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the VulnEqual.
// This includes values selected through modifiers, order, etc.
func (ve *VulnEqual) Value(name string) (ent.Value, error) {
	return ve.selectValues.Get(name)
}

// QueryVulnerabilityIds queries the "vulnerability_ids" edge of the VulnEqual entity.
func (ve *VulnEqual) QueryVulnerabilityIds() *VulnerabilityIDQuery {
	return NewVulnEqualClient(ve.config).QueryVulnerabilityIds(ve)
}

// Update returns a builder for updating this VulnEqual.
// Note that you need to call VulnEqual.Unwrap() before calling this method if this VulnEqual
// was returned from a transaction, and the transaction was committed or rolled back.
func (ve *VulnEqual) Update() *VulnEqualUpdateOne {
	return NewVulnEqualClient(ve.config).UpdateOne(ve)
}

// Unwrap unwraps the VulnEqual entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (ve *VulnEqual) Unwrap() *VulnEqual {
	_tx, ok := ve.config.driver.(*txDriver)
	if !ok {
		panic("ent: VulnEqual is not a transactional entity")
	}
	ve.config.driver = _tx.drv
	return ve
}

// String implements the fmt.Stringer.
func (ve *VulnEqual) String() string {
	var builder strings.Builder
	builder.WriteString("VulnEqual(")
	builder.WriteString(fmt.Sprintf("id=%v, ", ve.ID))
	builder.WriteString("justification=")
	builder.WriteString(ve.Justification)
	builder.WriteString(", ")
	builder.WriteString("origin=")
	builder.WriteString(ve.Origin)
	builder.WriteString(", ")
	builder.WriteString("collector=")
	builder.WriteString(ve.Collector)
	builder.WriteByte(')')
	return builder.String()
}

// NamedVulnerabilityIds returns the VulnerabilityIds named value or an error if the edge was not
// loaded in eager-loading with this name.
func (ve *VulnEqual) NamedVulnerabilityIds(name string) ([]*VulnerabilityID, error) {
	if ve.Edges.namedVulnerabilityIds == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := ve.Edges.namedVulnerabilityIds[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (ve *VulnEqual) appendNamedVulnerabilityIds(name string, edges ...*VulnerabilityID) {
	if ve.Edges.namedVulnerabilityIds == nil {
		ve.Edges.namedVulnerabilityIds = make(map[string][]*VulnerabilityID)
	}
	if len(edges) == 0 {
		ve.Edges.namedVulnerabilityIds[name] = []*VulnerabilityID{}
	} else {
		ve.Edges.namedVulnerabilityIds[name] = append(ve.Edges.namedVulnerabilityIds[name], edges...)
	}
}

// VulnEquals is a parsable slice of VulnEqual.
type VulnEquals []*VulnEqual
