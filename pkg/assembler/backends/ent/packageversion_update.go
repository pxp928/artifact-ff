// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/dialect/sql/sqljson"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/billofmaterials"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/occurrence"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/pkgequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// PackageVersionUpdate is the builder for updating PackageVersion entities.
type PackageVersionUpdate struct {
	config
	hooks    []Hook
	mutation *PackageVersionMutation
}

// Where appends a list predicates to the PackageVersionUpdate builder.
func (pvu *PackageVersionUpdate) Where(ps ...predicate.PackageVersion) *PackageVersionUpdate {
	pvu.mutation.Where(ps...)
	return pvu
}

// SetNameID sets the "name_id" field.
func (pvu *PackageVersionUpdate) SetNameID(u uuid.UUID) *PackageVersionUpdate {
	pvu.mutation.SetNameID(u)
	return pvu
}

// SetNillableNameID sets the "name_id" field if the given value is not nil.
func (pvu *PackageVersionUpdate) SetNillableNameID(u *uuid.UUID) *PackageVersionUpdate {
	if u != nil {
		pvu.SetNameID(*u)
	}
	return pvu
}

// SetVersion sets the "version" field.
func (pvu *PackageVersionUpdate) SetVersion(s string) *PackageVersionUpdate {
	pvu.mutation.SetVersion(s)
	return pvu
}

// SetNillableVersion sets the "version" field if the given value is not nil.
func (pvu *PackageVersionUpdate) SetNillableVersion(s *string) *PackageVersionUpdate {
	if s != nil {
		pvu.SetVersion(*s)
	}
	return pvu
}

// SetSubpath sets the "subpath" field.
func (pvu *PackageVersionUpdate) SetSubpath(s string) *PackageVersionUpdate {
	pvu.mutation.SetSubpath(s)
	return pvu
}

// SetNillableSubpath sets the "subpath" field if the given value is not nil.
func (pvu *PackageVersionUpdate) SetNillableSubpath(s *string) *PackageVersionUpdate {
	if s != nil {
		pvu.SetSubpath(*s)
	}
	return pvu
}

// SetQualifiers sets the "qualifiers" field.
func (pvu *PackageVersionUpdate) SetQualifiers(mq []model.PackageQualifier) *PackageVersionUpdate {
	pvu.mutation.SetQualifiers(mq)
	return pvu
}

// AppendQualifiers appends mq to the "qualifiers" field.
func (pvu *PackageVersionUpdate) AppendQualifiers(mq []model.PackageQualifier) *PackageVersionUpdate {
	pvu.mutation.AppendQualifiers(mq)
	return pvu
}

// ClearQualifiers clears the value of the "qualifiers" field.
func (pvu *PackageVersionUpdate) ClearQualifiers() *PackageVersionUpdate {
	pvu.mutation.ClearQualifiers()
	return pvu
}

// SetHash sets the "hash" field.
func (pvu *PackageVersionUpdate) SetHash(s string) *PackageVersionUpdate {
	pvu.mutation.SetHash(s)
	return pvu
}

// SetNillableHash sets the "hash" field if the given value is not nil.
func (pvu *PackageVersionUpdate) SetNillableHash(s *string) *PackageVersionUpdate {
	if s != nil {
		pvu.SetHash(*s)
	}
	return pvu
}

// SetName sets the "name" edge to the PackageName entity.
func (pvu *PackageVersionUpdate) SetName(p *PackageName) *PackageVersionUpdate {
	return pvu.SetNameID(p.ID)
}

// AddOccurrenceIDs adds the "occurrences" edge to the Occurrence entity by IDs.
func (pvu *PackageVersionUpdate) AddOccurrenceIDs(ids ...uuid.UUID) *PackageVersionUpdate {
	pvu.mutation.AddOccurrenceIDs(ids...)
	return pvu
}

// AddOccurrences adds the "occurrences" edges to the Occurrence entity.
func (pvu *PackageVersionUpdate) AddOccurrences(o ...*Occurrence) *PackageVersionUpdate {
	ids := make([]uuid.UUID, len(o))
	for i := range o {
		ids[i] = o[i].ID
	}
	return pvu.AddOccurrenceIDs(ids...)
}

// AddSbomIDs adds the "sbom" edge to the BillOfMaterials entity by IDs.
func (pvu *PackageVersionUpdate) AddSbomIDs(ids ...uuid.UUID) *PackageVersionUpdate {
	pvu.mutation.AddSbomIDs(ids...)
	return pvu
}

// AddSbom adds the "sbom" edges to the BillOfMaterials entity.
func (pvu *PackageVersionUpdate) AddSbom(b ...*BillOfMaterials) *PackageVersionUpdate {
	ids := make([]uuid.UUID, len(b))
	for i := range b {
		ids[i] = b[i].ID
	}
	return pvu.AddSbomIDs(ids...)
}

// AddEqualPackageIDs adds the "equal_packages" edge to the PkgEqual entity by IDs.
func (pvu *PackageVersionUpdate) AddEqualPackageIDs(ids ...uuid.UUID) *PackageVersionUpdate {
	pvu.mutation.AddEqualPackageIDs(ids...)
	return pvu
}

// AddEqualPackages adds the "equal_packages" edges to the PkgEqual entity.
func (pvu *PackageVersionUpdate) AddEqualPackages(p ...*PkgEqual) *PackageVersionUpdate {
	ids := make([]uuid.UUID, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return pvu.AddEqualPackageIDs(ids...)
}

// AddIncludedInSbomIDs adds the "included_in_sboms" edge to the BillOfMaterials entity by IDs.
func (pvu *PackageVersionUpdate) AddIncludedInSbomIDs(ids ...uuid.UUID) *PackageVersionUpdate {
	pvu.mutation.AddIncludedInSbomIDs(ids...)
	return pvu
}

// AddIncludedInSboms adds the "included_in_sboms" edges to the BillOfMaterials entity.
func (pvu *PackageVersionUpdate) AddIncludedInSboms(b ...*BillOfMaterials) *PackageVersionUpdate {
	ids := make([]uuid.UUID, len(b))
	for i := range b {
		ids[i] = b[i].ID
	}
	return pvu.AddIncludedInSbomIDs(ids...)
}

// Mutation returns the PackageVersionMutation object of the builder.
func (pvu *PackageVersionUpdate) Mutation() *PackageVersionMutation {
	return pvu.mutation
}

// ClearName clears the "name" edge to the PackageName entity.
func (pvu *PackageVersionUpdate) ClearName() *PackageVersionUpdate {
	pvu.mutation.ClearName()
	return pvu
}

// ClearOccurrences clears all "occurrences" edges to the Occurrence entity.
func (pvu *PackageVersionUpdate) ClearOccurrences() *PackageVersionUpdate {
	pvu.mutation.ClearOccurrences()
	return pvu
}

// RemoveOccurrenceIDs removes the "occurrences" edge to Occurrence entities by IDs.
func (pvu *PackageVersionUpdate) RemoveOccurrenceIDs(ids ...uuid.UUID) *PackageVersionUpdate {
	pvu.mutation.RemoveOccurrenceIDs(ids...)
	return pvu
}

// RemoveOccurrences removes "occurrences" edges to Occurrence entities.
func (pvu *PackageVersionUpdate) RemoveOccurrences(o ...*Occurrence) *PackageVersionUpdate {
	ids := make([]uuid.UUID, len(o))
	for i := range o {
		ids[i] = o[i].ID
	}
	return pvu.RemoveOccurrenceIDs(ids...)
}

// ClearSbom clears all "sbom" edges to the BillOfMaterials entity.
func (pvu *PackageVersionUpdate) ClearSbom() *PackageVersionUpdate {
	pvu.mutation.ClearSbom()
	return pvu
}

// RemoveSbomIDs removes the "sbom" edge to BillOfMaterials entities by IDs.
func (pvu *PackageVersionUpdate) RemoveSbomIDs(ids ...uuid.UUID) *PackageVersionUpdate {
	pvu.mutation.RemoveSbomIDs(ids...)
	return pvu
}

// RemoveSbom removes "sbom" edges to BillOfMaterials entities.
func (pvu *PackageVersionUpdate) RemoveSbom(b ...*BillOfMaterials) *PackageVersionUpdate {
	ids := make([]uuid.UUID, len(b))
	for i := range b {
		ids[i] = b[i].ID
	}
	return pvu.RemoveSbomIDs(ids...)
}

// ClearEqualPackages clears all "equal_packages" edges to the PkgEqual entity.
func (pvu *PackageVersionUpdate) ClearEqualPackages() *PackageVersionUpdate {
	pvu.mutation.ClearEqualPackages()
	return pvu
}

// RemoveEqualPackageIDs removes the "equal_packages" edge to PkgEqual entities by IDs.
func (pvu *PackageVersionUpdate) RemoveEqualPackageIDs(ids ...uuid.UUID) *PackageVersionUpdate {
	pvu.mutation.RemoveEqualPackageIDs(ids...)
	return pvu
}

// RemoveEqualPackages removes "equal_packages" edges to PkgEqual entities.
func (pvu *PackageVersionUpdate) RemoveEqualPackages(p ...*PkgEqual) *PackageVersionUpdate {
	ids := make([]uuid.UUID, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return pvu.RemoveEqualPackageIDs(ids...)
}

// ClearIncludedInSboms clears all "included_in_sboms" edges to the BillOfMaterials entity.
func (pvu *PackageVersionUpdate) ClearIncludedInSboms() *PackageVersionUpdate {
	pvu.mutation.ClearIncludedInSboms()
	return pvu
}

// RemoveIncludedInSbomIDs removes the "included_in_sboms" edge to BillOfMaterials entities by IDs.
func (pvu *PackageVersionUpdate) RemoveIncludedInSbomIDs(ids ...uuid.UUID) *PackageVersionUpdate {
	pvu.mutation.RemoveIncludedInSbomIDs(ids...)
	return pvu
}

// RemoveIncludedInSboms removes "included_in_sboms" edges to BillOfMaterials entities.
func (pvu *PackageVersionUpdate) RemoveIncludedInSboms(b ...*BillOfMaterials) *PackageVersionUpdate {
	ids := make([]uuid.UUID, len(b))
	for i := range b {
		ids[i] = b[i].ID
	}
	return pvu.RemoveIncludedInSbomIDs(ids...)
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (pvu *PackageVersionUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, pvu.sqlSave, pvu.mutation, pvu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (pvu *PackageVersionUpdate) SaveX(ctx context.Context) int {
	affected, err := pvu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (pvu *PackageVersionUpdate) Exec(ctx context.Context) error {
	_, err := pvu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (pvu *PackageVersionUpdate) ExecX(ctx context.Context) {
	if err := pvu.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (pvu *PackageVersionUpdate) check() error {
	if _, ok := pvu.mutation.NameID(); pvu.mutation.NameCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "PackageVersion.name"`)
	}
	return nil
}

func (pvu *PackageVersionUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := pvu.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(packageversion.Table, packageversion.Columns, sqlgraph.NewFieldSpec(packageversion.FieldID, field.TypeUUID))
	if ps := pvu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := pvu.mutation.Version(); ok {
		_spec.SetField(packageversion.FieldVersion, field.TypeString, value)
	}
	if value, ok := pvu.mutation.Subpath(); ok {
		_spec.SetField(packageversion.FieldSubpath, field.TypeString, value)
	}
	if value, ok := pvu.mutation.Qualifiers(); ok {
		_spec.SetField(packageversion.FieldQualifiers, field.TypeJSON, value)
	}
	if value, ok := pvu.mutation.AppendedQualifiers(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, packageversion.FieldQualifiers, value)
		})
	}
	if pvu.mutation.QualifiersCleared() {
		_spec.ClearField(packageversion.FieldQualifiers, field.TypeJSON)
	}
	if value, ok := pvu.mutation.Hash(); ok {
		_spec.SetField(packageversion.FieldHash, field.TypeString, value)
	}
	if pvu.mutation.NameCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   packageversion.NameTable,
			Columns: []string{packageversion.NameColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagename.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pvu.mutation.NameIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   packageversion.NameTable,
			Columns: []string{packageversion.NameColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagename.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if pvu.mutation.OccurrencesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   packageversion.OccurrencesTable,
			Columns: []string{packageversion.OccurrencesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(occurrence.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pvu.mutation.RemovedOccurrencesIDs(); len(nodes) > 0 && !pvu.mutation.OccurrencesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   packageversion.OccurrencesTable,
			Columns: []string{packageversion.OccurrencesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(occurrence.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pvu.mutation.OccurrencesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   packageversion.OccurrencesTable,
			Columns: []string{packageversion.OccurrencesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(occurrence.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if pvu.mutation.SbomCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   packageversion.SbomTable,
			Columns: []string{packageversion.SbomColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(billofmaterials.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pvu.mutation.RemovedSbomIDs(); len(nodes) > 0 && !pvu.mutation.SbomCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   packageversion.SbomTable,
			Columns: []string{packageversion.SbomColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(billofmaterials.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pvu.mutation.SbomIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   packageversion.SbomTable,
			Columns: []string{packageversion.SbomColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(billofmaterials.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if pvu.mutation.EqualPackagesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   packageversion.EqualPackagesTable,
			Columns: packageversion.EqualPackagesPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(pkgequal.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pvu.mutation.RemovedEqualPackagesIDs(); len(nodes) > 0 && !pvu.mutation.EqualPackagesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   packageversion.EqualPackagesTable,
			Columns: packageversion.EqualPackagesPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(pkgequal.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pvu.mutation.EqualPackagesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   packageversion.EqualPackagesTable,
			Columns: packageversion.EqualPackagesPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(pkgequal.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if pvu.mutation.IncludedInSbomsCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   packageversion.IncludedInSbomsTable,
			Columns: packageversion.IncludedInSbomsPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(billofmaterials.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pvu.mutation.RemovedIncludedInSbomsIDs(); len(nodes) > 0 && !pvu.mutation.IncludedInSbomsCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   packageversion.IncludedInSbomsTable,
			Columns: packageversion.IncludedInSbomsPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(billofmaterials.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pvu.mutation.IncludedInSbomsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   packageversion.IncludedInSbomsTable,
			Columns: packageversion.IncludedInSbomsPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(billofmaterials.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, pvu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{packageversion.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	pvu.mutation.done = true
	return n, nil
}

// PackageVersionUpdateOne is the builder for updating a single PackageVersion entity.
type PackageVersionUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *PackageVersionMutation
}

// SetNameID sets the "name_id" field.
func (pvuo *PackageVersionUpdateOne) SetNameID(u uuid.UUID) *PackageVersionUpdateOne {
	pvuo.mutation.SetNameID(u)
	return pvuo
}

// SetNillableNameID sets the "name_id" field if the given value is not nil.
func (pvuo *PackageVersionUpdateOne) SetNillableNameID(u *uuid.UUID) *PackageVersionUpdateOne {
	if u != nil {
		pvuo.SetNameID(*u)
	}
	return pvuo
}

// SetVersion sets the "version" field.
func (pvuo *PackageVersionUpdateOne) SetVersion(s string) *PackageVersionUpdateOne {
	pvuo.mutation.SetVersion(s)
	return pvuo
}

// SetNillableVersion sets the "version" field if the given value is not nil.
func (pvuo *PackageVersionUpdateOne) SetNillableVersion(s *string) *PackageVersionUpdateOne {
	if s != nil {
		pvuo.SetVersion(*s)
	}
	return pvuo
}

// SetSubpath sets the "subpath" field.
func (pvuo *PackageVersionUpdateOne) SetSubpath(s string) *PackageVersionUpdateOne {
	pvuo.mutation.SetSubpath(s)
	return pvuo
}

// SetNillableSubpath sets the "subpath" field if the given value is not nil.
func (pvuo *PackageVersionUpdateOne) SetNillableSubpath(s *string) *PackageVersionUpdateOne {
	if s != nil {
		pvuo.SetSubpath(*s)
	}
	return pvuo
}

// SetQualifiers sets the "qualifiers" field.
func (pvuo *PackageVersionUpdateOne) SetQualifiers(mq []model.PackageQualifier) *PackageVersionUpdateOne {
	pvuo.mutation.SetQualifiers(mq)
	return pvuo
}

// AppendQualifiers appends mq to the "qualifiers" field.
func (pvuo *PackageVersionUpdateOne) AppendQualifiers(mq []model.PackageQualifier) *PackageVersionUpdateOne {
	pvuo.mutation.AppendQualifiers(mq)
	return pvuo
}

// ClearQualifiers clears the value of the "qualifiers" field.
func (pvuo *PackageVersionUpdateOne) ClearQualifiers() *PackageVersionUpdateOne {
	pvuo.mutation.ClearQualifiers()
	return pvuo
}

// SetHash sets the "hash" field.
func (pvuo *PackageVersionUpdateOne) SetHash(s string) *PackageVersionUpdateOne {
	pvuo.mutation.SetHash(s)
	return pvuo
}

// SetNillableHash sets the "hash" field if the given value is not nil.
func (pvuo *PackageVersionUpdateOne) SetNillableHash(s *string) *PackageVersionUpdateOne {
	if s != nil {
		pvuo.SetHash(*s)
	}
	return pvuo
}

// SetName sets the "name" edge to the PackageName entity.
func (pvuo *PackageVersionUpdateOne) SetName(p *PackageName) *PackageVersionUpdateOne {
	return pvuo.SetNameID(p.ID)
}

// AddOccurrenceIDs adds the "occurrences" edge to the Occurrence entity by IDs.
func (pvuo *PackageVersionUpdateOne) AddOccurrenceIDs(ids ...uuid.UUID) *PackageVersionUpdateOne {
	pvuo.mutation.AddOccurrenceIDs(ids...)
	return pvuo
}

// AddOccurrences adds the "occurrences" edges to the Occurrence entity.
func (pvuo *PackageVersionUpdateOne) AddOccurrences(o ...*Occurrence) *PackageVersionUpdateOne {
	ids := make([]uuid.UUID, len(o))
	for i := range o {
		ids[i] = o[i].ID
	}
	return pvuo.AddOccurrenceIDs(ids...)
}

// AddSbomIDs adds the "sbom" edge to the BillOfMaterials entity by IDs.
func (pvuo *PackageVersionUpdateOne) AddSbomIDs(ids ...uuid.UUID) *PackageVersionUpdateOne {
	pvuo.mutation.AddSbomIDs(ids...)
	return pvuo
}

// AddSbom adds the "sbom" edges to the BillOfMaterials entity.
func (pvuo *PackageVersionUpdateOne) AddSbom(b ...*BillOfMaterials) *PackageVersionUpdateOne {
	ids := make([]uuid.UUID, len(b))
	for i := range b {
		ids[i] = b[i].ID
	}
	return pvuo.AddSbomIDs(ids...)
}

// AddEqualPackageIDs adds the "equal_packages" edge to the PkgEqual entity by IDs.
func (pvuo *PackageVersionUpdateOne) AddEqualPackageIDs(ids ...uuid.UUID) *PackageVersionUpdateOne {
	pvuo.mutation.AddEqualPackageIDs(ids...)
	return pvuo
}

// AddEqualPackages adds the "equal_packages" edges to the PkgEqual entity.
func (pvuo *PackageVersionUpdateOne) AddEqualPackages(p ...*PkgEqual) *PackageVersionUpdateOne {
	ids := make([]uuid.UUID, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return pvuo.AddEqualPackageIDs(ids...)
}

// AddIncludedInSbomIDs adds the "included_in_sboms" edge to the BillOfMaterials entity by IDs.
func (pvuo *PackageVersionUpdateOne) AddIncludedInSbomIDs(ids ...uuid.UUID) *PackageVersionUpdateOne {
	pvuo.mutation.AddIncludedInSbomIDs(ids...)
	return pvuo
}

// AddIncludedInSboms adds the "included_in_sboms" edges to the BillOfMaterials entity.
func (pvuo *PackageVersionUpdateOne) AddIncludedInSboms(b ...*BillOfMaterials) *PackageVersionUpdateOne {
	ids := make([]uuid.UUID, len(b))
	for i := range b {
		ids[i] = b[i].ID
	}
	return pvuo.AddIncludedInSbomIDs(ids...)
}

// Mutation returns the PackageVersionMutation object of the builder.
func (pvuo *PackageVersionUpdateOne) Mutation() *PackageVersionMutation {
	return pvuo.mutation
}

// ClearName clears the "name" edge to the PackageName entity.
func (pvuo *PackageVersionUpdateOne) ClearName() *PackageVersionUpdateOne {
	pvuo.mutation.ClearName()
	return pvuo
}

// ClearOccurrences clears all "occurrences" edges to the Occurrence entity.
func (pvuo *PackageVersionUpdateOne) ClearOccurrences() *PackageVersionUpdateOne {
	pvuo.mutation.ClearOccurrences()
	return pvuo
}

// RemoveOccurrenceIDs removes the "occurrences" edge to Occurrence entities by IDs.
func (pvuo *PackageVersionUpdateOne) RemoveOccurrenceIDs(ids ...uuid.UUID) *PackageVersionUpdateOne {
	pvuo.mutation.RemoveOccurrenceIDs(ids...)
	return pvuo
}

// RemoveOccurrences removes "occurrences" edges to Occurrence entities.
func (pvuo *PackageVersionUpdateOne) RemoveOccurrences(o ...*Occurrence) *PackageVersionUpdateOne {
	ids := make([]uuid.UUID, len(o))
	for i := range o {
		ids[i] = o[i].ID
	}
	return pvuo.RemoveOccurrenceIDs(ids...)
}

// ClearSbom clears all "sbom" edges to the BillOfMaterials entity.
func (pvuo *PackageVersionUpdateOne) ClearSbom() *PackageVersionUpdateOne {
	pvuo.mutation.ClearSbom()
	return pvuo
}

// RemoveSbomIDs removes the "sbom" edge to BillOfMaterials entities by IDs.
func (pvuo *PackageVersionUpdateOne) RemoveSbomIDs(ids ...uuid.UUID) *PackageVersionUpdateOne {
	pvuo.mutation.RemoveSbomIDs(ids...)
	return pvuo
}

// RemoveSbom removes "sbom" edges to BillOfMaterials entities.
func (pvuo *PackageVersionUpdateOne) RemoveSbom(b ...*BillOfMaterials) *PackageVersionUpdateOne {
	ids := make([]uuid.UUID, len(b))
	for i := range b {
		ids[i] = b[i].ID
	}
	return pvuo.RemoveSbomIDs(ids...)
}

// ClearEqualPackages clears all "equal_packages" edges to the PkgEqual entity.
func (pvuo *PackageVersionUpdateOne) ClearEqualPackages() *PackageVersionUpdateOne {
	pvuo.mutation.ClearEqualPackages()
	return pvuo
}

// RemoveEqualPackageIDs removes the "equal_packages" edge to PkgEqual entities by IDs.
func (pvuo *PackageVersionUpdateOne) RemoveEqualPackageIDs(ids ...uuid.UUID) *PackageVersionUpdateOne {
	pvuo.mutation.RemoveEqualPackageIDs(ids...)
	return pvuo
}

// RemoveEqualPackages removes "equal_packages" edges to PkgEqual entities.
func (pvuo *PackageVersionUpdateOne) RemoveEqualPackages(p ...*PkgEqual) *PackageVersionUpdateOne {
	ids := make([]uuid.UUID, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return pvuo.RemoveEqualPackageIDs(ids...)
}

// ClearIncludedInSboms clears all "included_in_sboms" edges to the BillOfMaterials entity.
func (pvuo *PackageVersionUpdateOne) ClearIncludedInSboms() *PackageVersionUpdateOne {
	pvuo.mutation.ClearIncludedInSboms()
	return pvuo
}

// RemoveIncludedInSbomIDs removes the "included_in_sboms" edge to BillOfMaterials entities by IDs.
func (pvuo *PackageVersionUpdateOne) RemoveIncludedInSbomIDs(ids ...uuid.UUID) *PackageVersionUpdateOne {
	pvuo.mutation.RemoveIncludedInSbomIDs(ids...)
	return pvuo
}

// RemoveIncludedInSboms removes "included_in_sboms" edges to BillOfMaterials entities.
func (pvuo *PackageVersionUpdateOne) RemoveIncludedInSboms(b ...*BillOfMaterials) *PackageVersionUpdateOne {
	ids := make([]uuid.UUID, len(b))
	for i := range b {
		ids[i] = b[i].ID
	}
	return pvuo.RemoveIncludedInSbomIDs(ids...)
}

// Where appends a list predicates to the PackageVersionUpdate builder.
func (pvuo *PackageVersionUpdateOne) Where(ps ...predicate.PackageVersion) *PackageVersionUpdateOne {
	pvuo.mutation.Where(ps...)
	return pvuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (pvuo *PackageVersionUpdateOne) Select(field string, fields ...string) *PackageVersionUpdateOne {
	pvuo.fields = append([]string{field}, fields...)
	return pvuo
}

// Save executes the query and returns the updated PackageVersion entity.
func (pvuo *PackageVersionUpdateOne) Save(ctx context.Context) (*PackageVersion, error) {
	return withHooks(ctx, pvuo.sqlSave, pvuo.mutation, pvuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (pvuo *PackageVersionUpdateOne) SaveX(ctx context.Context) *PackageVersion {
	node, err := pvuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (pvuo *PackageVersionUpdateOne) Exec(ctx context.Context) error {
	_, err := pvuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (pvuo *PackageVersionUpdateOne) ExecX(ctx context.Context) {
	if err := pvuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (pvuo *PackageVersionUpdateOne) check() error {
	if _, ok := pvuo.mutation.NameID(); pvuo.mutation.NameCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "PackageVersion.name"`)
	}
	return nil
}

func (pvuo *PackageVersionUpdateOne) sqlSave(ctx context.Context) (_node *PackageVersion, err error) {
	if err := pvuo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(packageversion.Table, packageversion.Columns, sqlgraph.NewFieldSpec(packageversion.FieldID, field.TypeUUID))
	id, ok := pvuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "PackageVersion.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := pvuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, packageversion.FieldID)
		for _, f := range fields {
			if !packageversion.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != packageversion.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := pvuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := pvuo.mutation.Version(); ok {
		_spec.SetField(packageversion.FieldVersion, field.TypeString, value)
	}
	if value, ok := pvuo.mutation.Subpath(); ok {
		_spec.SetField(packageversion.FieldSubpath, field.TypeString, value)
	}
	if value, ok := pvuo.mutation.Qualifiers(); ok {
		_spec.SetField(packageversion.FieldQualifiers, field.TypeJSON, value)
	}
	if value, ok := pvuo.mutation.AppendedQualifiers(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, packageversion.FieldQualifiers, value)
		})
	}
	if pvuo.mutation.QualifiersCleared() {
		_spec.ClearField(packageversion.FieldQualifiers, field.TypeJSON)
	}
	if value, ok := pvuo.mutation.Hash(); ok {
		_spec.SetField(packageversion.FieldHash, field.TypeString, value)
	}
	if pvuo.mutation.NameCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   packageversion.NameTable,
			Columns: []string{packageversion.NameColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagename.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pvuo.mutation.NameIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   packageversion.NameTable,
			Columns: []string{packageversion.NameColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagename.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if pvuo.mutation.OccurrencesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   packageversion.OccurrencesTable,
			Columns: []string{packageversion.OccurrencesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(occurrence.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pvuo.mutation.RemovedOccurrencesIDs(); len(nodes) > 0 && !pvuo.mutation.OccurrencesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   packageversion.OccurrencesTable,
			Columns: []string{packageversion.OccurrencesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(occurrence.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pvuo.mutation.OccurrencesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   packageversion.OccurrencesTable,
			Columns: []string{packageversion.OccurrencesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(occurrence.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if pvuo.mutation.SbomCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   packageversion.SbomTable,
			Columns: []string{packageversion.SbomColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(billofmaterials.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pvuo.mutation.RemovedSbomIDs(); len(nodes) > 0 && !pvuo.mutation.SbomCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   packageversion.SbomTable,
			Columns: []string{packageversion.SbomColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(billofmaterials.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pvuo.mutation.SbomIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   packageversion.SbomTable,
			Columns: []string{packageversion.SbomColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(billofmaterials.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if pvuo.mutation.EqualPackagesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   packageversion.EqualPackagesTable,
			Columns: packageversion.EqualPackagesPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(pkgequal.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pvuo.mutation.RemovedEqualPackagesIDs(); len(nodes) > 0 && !pvuo.mutation.EqualPackagesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   packageversion.EqualPackagesTable,
			Columns: packageversion.EqualPackagesPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(pkgequal.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pvuo.mutation.EqualPackagesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   packageversion.EqualPackagesTable,
			Columns: packageversion.EqualPackagesPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(pkgequal.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if pvuo.mutation.IncludedInSbomsCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   packageversion.IncludedInSbomsTable,
			Columns: packageversion.IncludedInSbomsPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(billofmaterials.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pvuo.mutation.RemovedIncludedInSbomsIDs(); len(nodes) > 0 && !pvuo.mutation.IncludedInSbomsCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   packageversion.IncludedInSbomsTable,
			Columns: packageversion.IncludedInSbomsPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(billofmaterials.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pvuo.mutation.IncludedInSbomsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   packageversion.IncludedInSbomsTable,
			Columns: packageversion.IncludedInSbomsPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(billofmaterials.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &PackageVersion{config: pvuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, pvuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{packageversion.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	pvuo.mutation.done = true
	return _node, nil
}
