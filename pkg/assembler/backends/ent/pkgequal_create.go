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
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/pkgequal"
)

// PkgEqualCreate is the builder for creating a PkgEqual entity.
type PkgEqualCreate struct {
	config
	mutation *PkgEqualMutation
	hooks    []Hook
	conflict []sql.ConflictOption
}

// SetOrigin sets the "origin" field.
func (pec *PkgEqualCreate) SetOrigin(s string) *PkgEqualCreate {
	pec.mutation.SetOrigin(s)
	return pec
}

// SetCollector sets the "collector" field.
func (pec *PkgEqualCreate) SetCollector(s string) *PkgEqualCreate {
	pec.mutation.SetCollector(s)
	return pec
}

// SetJustification sets the "justification" field.
func (pec *PkgEqualCreate) SetJustification(s string) *PkgEqualCreate {
	pec.mutation.SetJustification(s)
	return pec
}

// SetPackagesHash sets the "packages_hash" field.
func (pec *PkgEqualCreate) SetPackagesHash(s string) *PkgEqualCreate {
	pec.mutation.SetPackagesHash(s)
	return pec
}

// SetID sets the "id" field.
func (pec *PkgEqualCreate) SetID(u uuid.UUID) *PkgEqualCreate {
	pec.mutation.SetID(u)
	return pec
}

// SetNillableID sets the "id" field if the given value is not nil.
func (pec *PkgEqualCreate) SetNillableID(u *uuid.UUID) *PkgEqualCreate {
	if u != nil {
		pec.SetID(*u)
	}
	return pec
}

// AddPackageIDs adds the "packages" edge to the PackageVersion entity by IDs.
func (pec *PkgEqualCreate) AddPackageIDs(ids ...uuid.UUID) *PkgEqualCreate {
	pec.mutation.AddPackageIDs(ids...)
	return pec
}

// AddPackages adds the "packages" edges to the PackageVersion entity.
func (pec *PkgEqualCreate) AddPackages(p ...*PackageVersion) *PkgEqualCreate {
	ids := make([]uuid.UUID, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return pec.AddPackageIDs(ids...)
}

// Mutation returns the PkgEqualMutation object of the builder.
func (pec *PkgEqualCreate) Mutation() *PkgEqualMutation {
	return pec.mutation
}

// Save creates the PkgEqual in the database.
func (pec *PkgEqualCreate) Save(ctx context.Context) (*PkgEqual, error) {
	pec.defaults()
	return withHooks(ctx, pec.sqlSave, pec.mutation, pec.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (pec *PkgEqualCreate) SaveX(ctx context.Context) *PkgEqual {
	v, err := pec.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (pec *PkgEqualCreate) Exec(ctx context.Context) error {
	_, err := pec.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (pec *PkgEqualCreate) ExecX(ctx context.Context) {
	if err := pec.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (pec *PkgEqualCreate) defaults() {
	if _, ok := pec.mutation.ID(); !ok {
		v := pkgequal.DefaultID()
		pec.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (pec *PkgEqualCreate) check() error {
	if _, ok := pec.mutation.Origin(); !ok {
		return &ValidationError{Name: "origin", err: errors.New(`ent: missing required field "PkgEqual.origin"`)}
	}
	if _, ok := pec.mutation.Collector(); !ok {
		return &ValidationError{Name: "collector", err: errors.New(`ent: missing required field "PkgEqual.collector"`)}
	}
	if _, ok := pec.mutation.Justification(); !ok {
		return &ValidationError{Name: "justification", err: errors.New(`ent: missing required field "PkgEqual.justification"`)}
	}
	if _, ok := pec.mutation.PackagesHash(); !ok {
		return &ValidationError{Name: "packages_hash", err: errors.New(`ent: missing required field "PkgEqual.packages_hash"`)}
	}
	if len(pec.mutation.PackagesIDs()) == 0 {
		return &ValidationError{Name: "packages", err: errors.New(`ent: missing required edge "PkgEqual.packages"`)}
	}
	return nil
}

func (pec *PkgEqualCreate) sqlSave(ctx context.Context) (*PkgEqual, error) {
	if err := pec.check(); err != nil {
		return nil, err
	}
	_node, _spec := pec.createSpec()
	if err := sqlgraph.CreateNode(ctx, pec.driver, _spec); err != nil {
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
	pec.mutation.id = &_node.ID
	pec.mutation.done = true
	return _node, nil
}

func (pec *PkgEqualCreate) createSpec() (*PkgEqual, *sqlgraph.CreateSpec) {
	var (
		_node = &PkgEqual{config: pec.config}
		_spec = sqlgraph.NewCreateSpec(pkgequal.Table, sqlgraph.NewFieldSpec(pkgequal.FieldID, field.TypeUUID))
	)
	_spec.OnConflict = pec.conflict
	if id, ok := pec.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := pec.mutation.Origin(); ok {
		_spec.SetField(pkgequal.FieldOrigin, field.TypeString, value)
		_node.Origin = value
	}
	if value, ok := pec.mutation.Collector(); ok {
		_spec.SetField(pkgequal.FieldCollector, field.TypeString, value)
		_node.Collector = value
	}
	if value, ok := pec.mutation.Justification(); ok {
		_spec.SetField(pkgequal.FieldJustification, field.TypeString, value)
		_node.Justification = value
	}
	if value, ok := pec.mutation.PackagesHash(); ok {
		_spec.SetField(pkgequal.FieldPackagesHash, field.TypeString, value)
		_node.PackagesHash = value
	}
	if nodes := pec.mutation.PackagesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: false,
			Table:   pkgequal.PackagesTable,
			Columns: pkgequal.PackagesPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packageversion.FieldID, field.TypeUUID),
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
//	client.PkgEqual.Create().
//		SetOrigin(v).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.PkgEqualUpsert) {
//			SetOrigin(v+v).
//		}).
//		Exec(ctx)
func (pec *PkgEqualCreate) OnConflict(opts ...sql.ConflictOption) *PkgEqualUpsertOne {
	pec.conflict = opts
	return &PkgEqualUpsertOne{
		create: pec,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.PkgEqual.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (pec *PkgEqualCreate) OnConflictColumns(columns ...string) *PkgEqualUpsertOne {
	pec.conflict = append(pec.conflict, sql.ConflictColumns(columns...))
	return &PkgEqualUpsertOne{
		create: pec,
	}
}

type (
	// PkgEqualUpsertOne is the builder for "upsert"-ing
	//  one PkgEqual node.
	PkgEqualUpsertOne struct {
		create *PkgEqualCreate
	}

	// PkgEqualUpsert is the "OnConflict" setter.
	PkgEqualUpsert struct {
		*sql.UpdateSet
	}
)

// SetOrigin sets the "origin" field.
func (u *PkgEqualUpsert) SetOrigin(v string) *PkgEqualUpsert {
	u.Set(pkgequal.FieldOrigin, v)
	return u
}

// UpdateOrigin sets the "origin" field to the value that was provided on create.
func (u *PkgEqualUpsert) UpdateOrigin() *PkgEqualUpsert {
	u.SetExcluded(pkgequal.FieldOrigin)
	return u
}

// SetCollector sets the "collector" field.
func (u *PkgEqualUpsert) SetCollector(v string) *PkgEqualUpsert {
	u.Set(pkgequal.FieldCollector, v)
	return u
}

// UpdateCollector sets the "collector" field to the value that was provided on create.
func (u *PkgEqualUpsert) UpdateCollector() *PkgEqualUpsert {
	u.SetExcluded(pkgequal.FieldCollector)
	return u
}

// SetJustification sets the "justification" field.
func (u *PkgEqualUpsert) SetJustification(v string) *PkgEqualUpsert {
	u.Set(pkgequal.FieldJustification, v)
	return u
}

// UpdateJustification sets the "justification" field to the value that was provided on create.
func (u *PkgEqualUpsert) UpdateJustification() *PkgEqualUpsert {
	u.SetExcluded(pkgequal.FieldJustification)
	return u
}

// SetPackagesHash sets the "packages_hash" field.
func (u *PkgEqualUpsert) SetPackagesHash(v string) *PkgEqualUpsert {
	u.Set(pkgequal.FieldPackagesHash, v)
	return u
}

// UpdatePackagesHash sets the "packages_hash" field to the value that was provided on create.
func (u *PkgEqualUpsert) UpdatePackagesHash() *PkgEqualUpsert {
	u.SetExcluded(pkgequal.FieldPackagesHash)
	return u
}

// UpdateNewValues updates the mutable fields using the new values that were set on create except the ID field.
// Using this option is equivalent to using:
//
//	client.PkgEqual.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(pkgequal.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *PkgEqualUpsertOne) UpdateNewValues() *PkgEqualUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		if _, exists := u.create.mutation.ID(); exists {
			s.SetIgnore(pkgequal.FieldID)
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.PkgEqual.Create().
//	    OnConflict(sql.ResolveWithIgnore()).
//	    Exec(ctx)
func (u *PkgEqualUpsertOne) Ignore() *PkgEqualUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *PkgEqualUpsertOne) DoNothing() *PkgEqualUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the PkgEqualCreate.OnConflict
// documentation for more info.
func (u *PkgEqualUpsertOne) Update(set func(*PkgEqualUpsert)) *PkgEqualUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&PkgEqualUpsert{UpdateSet: update})
	}))
	return u
}

// SetOrigin sets the "origin" field.
func (u *PkgEqualUpsertOne) SetOrigin(v string) *PkgEqualUpsertOne {
	return u.Update(func(s *PkgEqualUpsert) {
		s.SetOrigin(v)
	})
}

// UpdateOrigin sets the "origin" field to the value that was provided on create.
func (u *PkgEqualUpsertOne) UpdateOrigin() *PkgEqualUpsertOne {
	return u.Update(func(s *PkgEqualUpsert) {
		s.UpdateOrigin()
	})
}

// SetCollector sets the "collector" field.
func (u *PkgEqualUpsertOne) SetCollector(v string) *PkgEqualUpsertOne {
	return u.Update(func(s *PkgEqualUpsert) {
		s.SetCollector(v)
	})
}

// UpdateCollector sets the "collector" field to the value that was provided on create.
func (u *PkgEqualUpsertOne) UpdateCollector() *PkgEqualUpsertOne {
	return u.Update(func(s *PkgEqualUpsert) {
		s.UpdateCollector()
	})
}

// SetJustification sets the "justification" field.
func (u *PkgEqualUpsertOne) SetJustification(v string) *PkgEqualUpsertOne {
	return u.Update(func(s *PkgEqualUpsert) {
		s.SetJustification(v)
	})
}

// UpdateJustification sets the "justification" field to the value that was provided on create.
func (u *PkgEqualUpsertOne) UpdateJustification() *PkgEqualUpsertOne {
	return u.Update(func(s *PkgEqualUpsert) {
		s.UpdateJustification()
	})
}

// SetPackagesHash sets the "packages_hash" field.
func (u *PkgEqualUpsertOne) SetPackagesHash(v string) *PkgEqualUpsertOne {
	return u.Update(func(s *PkgEqualUpsert) {
		s.SetPackagesHash(v)
	})
}

// UpdatePackagesHash sets the "packages_hash" field to the value that was provided on create.
func (u *PkgEqualUpsertOne) UpdatePackagesHash() *PkgEqualUpsertOne {
	return u.Update(func(s *PkgEqualUpsert) {
		s.UpdatePackagesHash()
	})
}

// Exec executes the query.
func (u *PkgEqualUpsertOne) Exec(ctx context.Context) error {
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for PkgEqualCreate.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *PkgEqualUpsertOne) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}

// Exec executes the UPSERT query and returns the inserted/updated ID.
func (u *PkgEqualUpsertOne) ID(ctx context.Context) (id uuid.UUID, err error) {
	if u.create.driver.Dialect() == dialect.MySQL {
		// In case of "ON CONFLICT", there is no way to get back non-numeric ID
		// fields from the database since MySQL does not support the RETURNING clause.
		return id, errors.New("ent: PkgEqualUpsertOne.ID is not supported by MySQL driver. Use PkgEqualUpsertOne.Exec instead")
	}
	node, err := u.create.Save(ctx)
	if err != nil {
		return id, err
	}
	return node.ID, nil
}

// IDX is like ID, but panics if an error occurs.
func (u *PkgEqualUpsertOne) IDX(ctx context.Context) uuid.UUID {
	id, err := u.ID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// PkgEqualCreateBulk is the builder for creating many PkgEqual entities in bulk.
type PkgEqualCreateBulk struct {
	config
	err      error
	builders []*PkgEqualCreate
	conflict []sql.ConflictOption
}

// Save creates the PkgEqual entities in the database.
func (pecb *PkgEqualCreateBulk) Save(ctx context.Context) ([]*PkgEqual, error) {
	if pecb.err != nil {
		return nil, pecb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(pecb.builders))
	nodes := make([]*PkgEqual, len(pecb.builders))
	mutators := make([]Mutator, len(pecb.builders))
	for i := range pecb.builders {
		func(i int, root context.Context) {
			builder := pecb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*PkgEqualMutation)
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
					_, err = mutators[i+1].Mutate(root, pecb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					spec.OnConflict = pecb.conflict
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, pecb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, pecb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (pecb *PkgEqualCreateBulk) SaveX(ctx context.Context) []*PkgEqual {
	v, err := pecb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (pecb *PkgEqualCreateBulk) Exec(ctx context.Context) error {
	_, err := pecb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (pecb *PkgEqualCreateBulk) ExecX(ctx context.Context) {
	if err := pecb.Exec(ctx); err != nil {
		panic(err)
	}
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.PkgEqual.CreateBulk(builders...).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.PkgEqualUpsert) {
//			SetOrigin(v+v).
//		}).
//		Exec(ctx)
func (pecb *PkgEqualCreateBulk) OnConflict(opts ...sql.ConflictOption) *PkgEqualUpsertBulk {
	pecb.conflict = opts
	return &PkgEqualUpsertBulk{
		create: pecb,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.PkgEqual.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (pecb *PkgEqualCreateBulk) OnConflictColumns(columns ...string) *PkgEqualUpsertBulk {
	pecb.conflict = append(pecb.conflict, sql.ConflictColumns(columns...))
	return &PkgEqualUpsertBulk{
		create: pecb,
	}
}

// PkgEqualUpsertBulk is the builder for "upsert"-ing
// a bulk of PkgEqual nodes.
type PkgEqualUpsertBulk struct {
	create *PkgEqualCreateBulk
}

// UpdateNewValues updates the mutable fields using the new values that
// were set on create. Using this option is equivalent to using:
//
//	client.PkgEqual.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(pkgequal.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *PkgEqualUpsertBulk) UpdateNewValues() *PkgEqualUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		for _, b := range u.create.builders {
			if _, exists := b.mutation.ID(); exists {
				s.SetIgnore(pkgequal.FieldID)
			}
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.PkgEqual.Create().
//		OnConflict(sql.ResolveWithIgnore()).
//		Exec(ctx)
func (u *PkgEqualUpsertBulk) Ignore() *PkgEqualUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *PkgEqualUpsertBulk) DoNothing() *PkgEqualUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the PkgEqualCreateBulk.OnConflict
// documentation for more info.
func (u *PkgEqualUpsertBulk) Update(set func(*PkgEqualUpsert)) *PkgEqualUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&PkgEqualUpsert{UpdateSet: update})
	}))
	return u
}

// SetOrigin sets the "origin" field.
func (u *PkgEqualUpsertBulk) SetOrigin(v string) *PkgEqualUpsertBulk {
	return u.Update(func(s *PkgEqualUpsert) {
		s.SetOrigin(v)
	})
}

// UpdateOrigin sets the "origin" field to the value that was provided on create.
func (u *PkgEqualUpsertBulk) UpdateOrigin() *PkgEqualUpsertBulk {
	return u.Update(func(s *PkgEqualUpsert) {
		s.UpdateOrigin()
	})
}

// SetCollector sets the "collector" field.
func (u *PkgEqualUpsertBulk) SetCollector(v string) *PkgEqualUpsertBulk {
	return u.Update(func(s *PkgEqualUpsert) {
		s.SetCollector(v)
	})
}

// UpdateCollector sets the "collector" field to the value that was provided on create.
func (u *PkgEqualUpsertBulk) UpdateCollector() *PkgEqualUpsertBulk {
	return u.Update(func(s *PkgEqualUpsert) {
		s.UpdateCollector()
	})
}

// SetJustification sets the "justification" field.
func (u *PkgEqualUpsertBulk) SetJustification(v string) *PkgEqualUpsertBulk {
	return u.Update(func(s *PkgEqualUpsert) {
		s.SetJustification(v)
	})
}

// UpdateJustification sets the "justification" field to the value that was provided on create.
func (u *PkgEqualUpsertBulk) UpdateJustification() *PkgEqualUpsertBulk {
	return u.Update(func(s *PkgEqualUpsert) {
		s.UpdateJustification()
	})
}

// SetPackagesHash sets the "packages_hash" field.
func (u *PkgEqualUpsertBulk) SetPackagesHash(v string) *PkgEqualUpsertBulk {
	return u.Update(func(s *PkgEqualUpsert) {
		s.SetPackagesHash(v)
	})
}

// UpdatePackagesHash sets the "packages_hash" field to the value that was provided on create.
func (u *PkgEqualUpsertBulk) UpdatePackagesHash() *PkgEqualUpsertBulk {
	return u.Update(func(s *PkgEqualUpsert) {
		s.UpdatePackagesHash()
	})
}

// Exec executes the query.
func (u *PkgEqualUpsertBulk) Exec(ctx context.Context) error {
	if u.create.err != nil {
		return u.create.err
	}
	for i, b := range u.create.builders {
		if len(b.conflict) != 0 {
			return fmt.Errorf("ent: OnConflict was set for builder %d. Set it on the PkgEqualCreateBulk instead", i)
		}
	}
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for PkgEqualCreateBulk.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *PkgEqualUpsertBulk) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}
