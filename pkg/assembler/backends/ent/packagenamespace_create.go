// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagetype"
)

// PackageNamespaceCreate is the builder for creating a PackageNamespace entity.
type PackageNamespaceCreate struct {
	config
	mutation *PackageNamespaceMutation
	hooks    []Hook
	conflict []sql.ConflictOption
}

// SetPackageID sets the "package_id" field.
func (pnc *PackageNamespaceCreate) SetPackageID(u uuid.UUID) *PackageNamespaceCreate {
	pnc.mutation.SetPackageID(u)
	return pnc
}

// SetNamespace sets the "namespace" field.
func (pnc *PackageNamespaceCreate) SetNamespace(s string) *PackageNamespaceCreate {
	pnc.mutation.SetNamespace(s)
	return pnc
}

// SetID sets the "id" field.
func (pnc *PackageNamespaceCreate) SetID(u uuid.UUID) *PackageNamespaceCreate {
	pnc.mutation.SetID(u)
	return pnc
}

// SetNillableID sets the "id" field if the given value is not nil.
func (pnc *PackageNamespaceCreate) SetNillableID(u *uuid.UUID) *PackageNamespaceCreate {
	if u != nil {
		pnc.SetID(*u)
	}
	return pnc
}

// SetPackage sets the "package" edge to the PackageType entity.
func (pnc *PackageNamespaceCreate) SetPackage(p *PackageType) *PackageNamespaceCreate {
	return pnc.SetPackageID(p.ID)
}

// AddNameIDs adds the "names" edge to the PackageName entity by IDs.
func (pnc *PackageNamespaceCreate) AddNameIDs(ids ...uuid.UUID) *PackageNamespaceCreate {
	pnc.mutation.AddNameIDs(ids...)
	return pnc
}

// AddNames adds the "names" edges to the PackageName entity.
func (pnc *PackageNamespaceCreate) AddNames(p ...*PackageName) *PackageNamespaceCreate {
	ids := make([]uuid.UUID, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return pnc.AddNameIDs(ids...)
}

// Mutation returns the PackageNamespaceMutation object of the builder.
func (pnc *PackageNamespaceCreate) Mutation() *PackageNamespaceMutation {
	return pnc.mutation
}

// Save creates the PackageNamespace in the database.
func (pnc *PackageNamespaceCreate) Save(ctx context.Context) (*PackageNamespace, error) {
	pnc.defaults()
	return withHooks(ctx, pnc.sqlSave, pnc.mutation, pnc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (pnc *PackageNamespaceCreate) SaveX(ctx context.Context) *PackageNamespace {
	v, err := pnc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (pnc *PackageNamespaceCreate) Exec(ctx context.Context) error {
	_, err := pnc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (pnc *PackageNamespaceCreate) ExecX(ctx context.Context) {
	if err := pnc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (pnc *PackageNamespaceCreate) defaults() {
	if _, ok := pnc.mutation.ID(); !ok {
		v := packagenamespace.DefaultID()
		pnc.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (pnc *PackageNamespaceCreate) check() error {
	if _, ok := pnc.mutation.PackageID(); !ok {
		return &ValidationError{Name: "package_id", err: errors.New(`ent: missing required field "PackageNamespace.package_id"`)}
	}
	if _, ok := pnc.mutation.Namespace(); !ok {
		return &ValidationError{Name: "namespace", err: errors.New(`ent: missing required field "PackageNamespace.namespace"`)}
	}
	if _, ok := pnc.mutation.PackageID(); !ok {
		return &ValidationError{Name: "package", err: errors.New(`ent: missing required edge "PackageNamespace.package"`)}
	}
	return nil
}

func (pnc *PackageNamespaceCreate) sqlSave(ctx context.Context) (*PackageNamespace, error) {
	if err := pnc.check(); err != nil {
		return nil, err
	}
	_node, _spec := pnc.createSpec()
	if err := sqlgraph.CreateNode(ctx, pnc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(*uuid.UUID); ok {
			_node.ID = *id
		} else if err := _node.ID.Scan(_spec.ID.Value); err != nil {
			return nil, err
		}
	}
	pnc.mutation.id = &_node.ID
	pnc.mutation.done = true
	return _node, nil
}

func (pnc *PackageNamespaceCreate) createSpec() (*PackageNamespace, *sqlgraph.CreateSpec) {
	var (
		_node = &PackageNamespace{config: pnc.config}
		_spec = sqlgraph.NewCreateSpec(packagenamespace.Table, sqlgraph.NewFieldSpec(packagenamespace.FieldID, field.TypeUUID))
	)
	_spec.OnConflict = pnc.conflict
	if id, ok := pnc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := pnc.mutation.Namespace(); ok {
		_spec.SetField(packagenamespace.FieldNamespace, field.TypeString, value)
		_node.Namespace = value
	}
	if nodes := pnc.mutation.PackageIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   packagenamespace.PackageTable,
			Columns: []string{packagenamespace.PackageColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagetype.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.PackageID = nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := pnc.mutation.NamesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   packagenamespace.NamesTable,
			Columns: []string{packagenamespace.NamesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagename.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.PackageNamespace.Create().
//		SetPackageID(v).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.PackageNamespaceUpsert) {
//			SetPackageID(v+v).
//		}).
//		Exec(ctx)
func (pnc *PackageNamespaceCreate) OnConflict(opts ...sql.ConflictOption) *PackageNamespaceUpsertOne {
	pnc.conflict = opts
	return &PackageNamespaceUpsertOne{
		create: pnc,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.PackageNamespace.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (pnc *PackageNamespaceCreate) OnConflictColumns(columns ...string) *PackageNamespaceUpsertOne {
	pnc.conflict = append(pnc.conflict, sql.ConflictColumns(columns...))
	return &PackageNamespaceUpsertOne{
		create: pnc,
	}
}

type (
	// PackageNamespaceUpsertOne is the builder for "upsert"-ing
	//  one PackageNamespace node.
	PackageNamespaceUpsertOne struct {
		create *PackageNamespaceCreate
	}

	// PackageNamespaceUpsert is the "OnConflict" setter.
	PackageNamespaceUpsert struct {
		*sql.UpdateSet
	}
)

// SetPackageID sets the "package_id" field.
func (u *PackageNamespaceUpsert) SetPackageID(v uuid.UUID) *PackageNamespaceUpsert {
	u.Set(packagenamespace.FieldPackageID, v)
	return u
}

// UpdatePackageID sets the "package_id" field to the value that was provided on create.
func (u *PackageNamespaceUpsert) UpdatePackageID() *PackageNamespaceUpsert {
	u.SetExcluded(packagenamespace.FieldPackageID)
	return u
}

// SetNamespace sets the "namespace" field.
func (u *PackageNamespaceUpsert) SetNamespace(v string) *PackageNamespaceUpsert {
	u.Set(packagenamespace.FieldNamespace, v)
	return u
}

// UpdateNamespace sets the "namespace" field to the value that was provided on create.
func (u *PackageNamespaceUpsert) UpdateNamespace() *PackageNamespaceUpsert {
	u.SetExcluded(packagenamespace.FieldNamespace)
	return u
}

// UpdateNewValues updates the mutable fields using the new values that were set on create except the ID field.
// Using this option is equivalent to using:
//
//	client.PackageNamespace.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(packagenamespace.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *PackageNamespaceUpsertOne) UpdateNewValues() *PackageNamespaceUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		if _, exists := u.create.mutation.ID(); exists {
			s.SetIgnore(packagenamespace.FieldID)
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.PackageNamespace.Create().
//	    OnConflict(sql.ResolveWithIgnore()).
//	    Exec(ctx)
func (u *PackageNamespaceUpsertOne) Ignore() *PackageNamespaceUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *PackageNamespaceUpsertOne) DoNothing() *PackageNamespaceUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the PackageNamespaceCreate.OnConflict
// documentation for more info.
func (u *PackageNamespaceUpsertOne) Update(set func(*PackageNamespaceUpsert)) *PackageNamespaceUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&PackageNamespaceUpsert{UpdateSet: update})
	}))
	return u
}

// SetPackageID sets the "package_id" field.
func (u *PackageNamespaceUpsertOne) SetPackageID(v uuid.UUID) *PackageNamespaceUpsertOne {
	return u.Update(func(s *PackageNamespaceUpsert) {
		s.SetPackageID(v)
	})
}

// UpdatePackageID sets the "package_id" field to the value that was provided on create.
func (u *PackageNamespaceUpsertOne) UpdatePackageID() *PackageNamespaceUpsertOne {
	return u.Update(func(s *PackageNamespaceUpsert) {
		s.UpdatePackageID()
	})
}

// SetNamespace sets the "namespace" field.
func (u *PackageNamespaceUpsertOne) SetNamespace(v string) *PackageNamespaceUpsertOne {
	return u.Update(func(s *PackageNamespaceUpsert) {
		s.SetNamespace(v)
	})
}

// UpdateNamespace sets the "namespace" field to the value that was provided on create.
func (u *PackageNamespaceUpsertOne) UpdateNamespace() *PackageNamespaceUpsertOne {
	return u.Update(func(s *PackageNamespaceUpsert) {
		s.UpdateNamespace()
	})
}

// Exec executes the query.
func (u *PackageNamespaceUpsertOne) Exec(ctx context.Context) error {
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for PackageNamespaceCreate.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *PackageNamespaceUpsertOne) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}

// Exec executes the UPSERT query and returns the inserted/updated ID.
func (u *PackageNamespaceUpsertOne) ID(ctx context.Context) (id uuid.UUID, err error) {
	if u.create.driver.Dialect() == dialect.MySQL {
		// In case of "ON CONFLICT", there is no way to get back non-numeric ID
		// fields from the database since MySQL does not support the RETURNING clause.
		return id, errors.New("ent: PackageNamespaceUpsertOne.ID is not supported by MySQL driver. Use PackageNamespaceUpsertOne.Exec instead")
	}
	node, err := u.create.Save(ctx)
	if err != nil {
		return id, err
	}
	return node.ID, nil
}

// IDX is like ID, but panics if an error occurs.
func (u *PackageNamespaceUpsertOne) IDX(ctx context.Context) uuid.UUID {
	id, err := u.ID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// PackageNamespaceCreateBulk is the builder for creating many PackageNamespace entities in bulk.
type PackageNamespaceCreateBulk struct {
	config
	err      error
	builders []*PackageNamespaceCreate
	conflict []sql.ConflictOption
}

// Save creates the PackageNamespace entities in the database.
func (pncb *PackageNamespaceCreateBulk) Save(ctx context.Context) ([]*PackageNamespace, error) {
	if pncb.err != nil {
		return nil, pncb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(pncb.builders))
	nodes := make([]*PackageNamespace, len(pncb.builders))
	mutators := make([]Mutator, len(pncb.builders))
	for i := range pncb.builders {
		func(i int, root context.Context) {
			builder := pncb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*PackageNamespaceMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, pncb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					spec.OnConflict = pncb.conflict
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, pncb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, pncb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (pncb *PackageNamespaceCreateBulk) SaveX(ctx context.Context) []*PackageNamespace {
	v, err := pncb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (pncb *PackageNamespaceCreateBulk) Exec(ctx context.Context) error {
	_, err := pncb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (pncb *PackageNamespaceCreateBulk) ExecX(ctx context.Context) {
	if err := pncb.Exec(ctx); err != nil {
		panic(err)
	}
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.PackageNamespace.CreateBulk(builders...).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.PackageNamespaceUpsert) {
//			SetPackageID(v+v).
//		}).
//		Exec(ctx)
func (pncb *PackageNamespaceCreateBulk) OnConflict(opts ...sql.ConflictOption) *PackageNamespaceUpsertBulk {
	pncb.conflict = opts
	return &PackageNamespaceUpsertBulk{
		create: pncb,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.PackageNamespace.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (pncb *PackageNamespaceCreateBulk) OnConflictColumns(columns ...string) *PackageNamespaceUpsertBulk {
	pncb.conflict = append(pncb.conflict, sql.ConflictColumns(columns...))
	return &PackageNamespaceUpsertBulk{
		create: pncb,
	}
}

// PackageNamespaceUpsertBulk is the builder for "upsert"-ing
// a bulk of PackageNamespace nodes.
type PackageNamespaceUpsertBulk struct {
	create *PackageNamespaceCreateBulk
}

// UpdateNewValues updates the mutable fields using the new values that
// were set on create. Using this option is equivalent to using:
//
//	client.PackageNamespace.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(packagenamespace.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *PackageNamespaceUpsertBulk) UpdateNewValues() *PackageNamespaceUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		for _, b := range u.create.builders {
			if _, exists := b.mutation.ID(); exists {
				s.SetIgnore(packagenamespace.FieldID)
			}
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.PackageNamespace.Create().
//		OnConflict(sql.ResolveWithIgnore()).
//		Exec(ctx)
func (u *PackageNamespaceUpsertBulk) Ignore() *PackageNamespaceUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *PackageNamespaceUpsertBulk) DoNothing() *PackageNamespaceUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the PackageNamespaceCreateBulk.OnConflict
// documentation for more info.
func (u *PackageNamespaceUpsertBulk) Update(set func(*PackageNamespaceUpsert)) *PackageNamespaceUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&PackageNamespaceUpsert{UpdateSet: update})
	}))
	return u
}

// SetPackageID sets the "package_id" field.
func (u *PackageNamespaceUpsertBulk) SetPackageID(v uuid.UUID) *PackageNamespaceUpsertBulk {
	return u.Update(func(s *PackageNamespaceUpsert) {
		s.SetPackageID(v)
	})
}

// UpdatePackageID sets the "package_id" field to the value that was provided on create.
func (u *PackageNamespaceUpsertBulk) UpdatePackageID() *PackageNamespaceUpsertBulk {
	return u.Update(func(s *PackageNamespaceUpsert) {
		s.UpdatePackageID()
	})
}

// SetNamespace sets the "namespace" field.
func (u *PackageNamespaceUpsertBulk) SetNamespace(v string) *PackageNamespaceUpsertBulk {
	return u.Update(func(s *PackageNamespaceUpsert) {
		s.SetNamespace(v)
	})
}

// UpdateNamespace sets the "namespace" field to the value that was provided on create.
func (u *PackageNamespaceUpsertBulk) UpdateNamespace() *PackageNamespaceUpsertBulk {
	return u.Update(func(s *PackageNamespaceUpsert) {
		s.UpdateNamespace()
	})
}

// Exec executes the query.
func (u *PackageNamespaceUpsertBulk) Exec(ctx context.Context) error {
	if u.create.err != nil {
		return u.create.err
	}
	for i, b := range u.create.builders {
		if len(b.conflict) != 0 {
			return fmt.Errorf("ent: OnConflict was set for builder %d. Set it on the PackageNamespaceCreateBulk instead", i)
		}
	}
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for PackageNamespaceCreateBulk.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *PackageNamespaceUpsertBulk) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}
