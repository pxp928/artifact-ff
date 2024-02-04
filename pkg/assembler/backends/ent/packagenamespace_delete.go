// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
)

// PackageNamespaceDelete is the builder for deleting a PackageNamespace entity.
type PackageNamespaceDelete struct {
	config
	hooks    []Hook
	mutation *PackageNamespaceMutation
}

// Where appends a list predicates to the PackageNamespaceDelete builder.
func (pnd *PackageNamespaceDelete) Where(ps ...predicate.PackageNamespace) *PackageNamespaceDelete {
	pnd.mutation.Where(ps...)
	return pnd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (pnd *PackageNamespaceDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, pnd.sqlExec, pnd.mutation, pnd.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (pnd *PackageNamespaceDelete) ExecX(ctx context.Context) int {
	n, err := pnd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (pnd *PackageNamespaceDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(packagenamespace.Table, sqlgraph.NewFieldSpec(packagenamespace.FieldID, field.TypeUUID))
	if ps := pnd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, pnd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	pnd.mutation.done = true
	return affected, err
}

// PackageNamespaceDeleteOne is the builder for deleting a single PackageNamespace entity.
type PackageNamespaceDeleteOne struct {
	pnd *PackageNamespaceDelete
}

// Where appends a list predicates to the PackageNamespaceDelete builder.
func (pndo *PackageNamespaceDeleteOne) Where(ps ...predicate.PackageNamespace) *PackageNamespaceDeleteOne {
	pndo.pnd.mutation.Where(ps...)
	return pndo
}

// Exec executes the deletion query.
func (pndo *PackageNamespaceDeleteOne) Exec(ctx context.Context) error {
	n, err := pndo.pnd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{packagenamespace.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (pndo *PackageNamespaceDeleteOne) ExecX(ctx context.Context) {
	if err := pndo.Exec(ctx); err != nil {
		panic(err)
	}
}
