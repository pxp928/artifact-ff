// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"database/sql/driver"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/billofmaterials"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/dependency"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
)

// DependencyQuery is the builder for querying Dependency entities.
type DependencyQuery struct {
	config
	ctx                         *QueryContext
	order                       []dependency.OrderOption
	inters                      []Interceptor
	predicates                  []predicate.Dependency
	withPackage                 *PackageVersionQuery
	withDependentPackageName    *PackageNameQuery
	withDependentPackageVersion *PackageVersionQuery
	withIncludedInSboms         *BillOfMaterialsQuery
	modifiers                   []func(*sql.Selector)
	loadTotal                   []func(context.Context, []*Dependency) error
	withNamedIncludedInSboms    map[string]*BillOfMaterialsQuery
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the DependencyQuery builder.
func (dq *DependencyQuery) Where(ps ...predicate.Dependency) *DependencyQuery {
	dq.predicates = append(dq.predicates, ps...)
	return dq
}

// Limit the number of records to be returned by this query.
func (dq *DependencyQuery) Limit(limit int) *DependencyQuery {
	dq.ctx.Limit = &limit
	return dq
}

// Offset to start from.
func (dq *DependencyQuery) Offset(offset int) *DependencyQuery {
	dq.ctx.Offset = &offset
	return dq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (dq *DependencyQuery) Unique(unique bool) *DependencyQuery {
	dq.ctx.Unique = &unique
	return dq
}

// Order specifies how the records should be ordered.
func (dq *DependencyQuery) Order(o ...dependency.OrderOption) *DependencyQuery {
	dq.order = append(dq.order, o...)
	return dq
}

// QueryPackage chains the current query on the "package" edge.
func (dq *DependencyQuery) QueryPackage() *PackageVersionQuery {
	query := (&PackageVersionClient{config: dq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := dq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := dq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(dependency.Table, dependency.FieldID, selector),
			sqlgraph.To(packageversion.Table, packageversion.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, dependency.PackageTable, dependency.PackageColumn),
		)
		fromU = sqlgraph.SetNeighbors(dq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryDependentPackageName chains the current query on the "dependent_package_name" edge.
func (dq *DependencyQuery) QueryDependentPackageName() *PackageNameQuery {
	query := (&PackageNameClient{config: dq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := dq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := dq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(dependency.Table, dependency.FieldID, selector),
			sqlgraph.To(packagename.Table, packagename.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, dependency.DependentPackageNameTable, dependency.DependentPackageNameColumn),
		)
		fromU = sqlgraph.SetNeighbors(dq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryDependentPackageVersion chains the current query on the "dependent_package_version" edge.
func (dq *DependencyQuery) QueryDependentPackageVersion() *PackageVersionQuery {
	query := (&PackageVersionClient{config: dq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := dq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := dq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(dependency.Table, dependency.FieldID, selector),
			sqlgraph.To(packageversion.Table, packageversion.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, dependency.DependentPackageVersionTable, dependency.DependentPackageVersionColumn),
		)
		fromU = sqlgraph.SetNeighbors(dq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryIncludedInSboms chains the current query on the "included_in_sboms" edge.
func (dq *DependencyQuery) QueryIncludedInSboms() *BillOfMaterialsQuery {
	query := (&BillOfMaterialsClient{config: dq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := dq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := dq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(dependency.Table, dependency.FieldID, selector),
			sqlgraph.To(billofmaterials.Table, billofmaterials.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, dependency.IncludedInSbomsTable, dependency.IncludedInSbomsPrimaryKey...),
		)
		fromU = sqlgraph.SetNeighbors(dq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first Dependency entity from the query.
// Returns a *NotFoundError when no Dependency was found.
func (dq *DependencyQuery) First(ctx context.Context) (*Dependency, error) {
	nodes, err := dq.Limit(1).All(setContextOp(ctx, dq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{dependency.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (dq *DependencyQuery) FirstX(ctx context.Context) *Dependency {
	node, err := dq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first Dependency ID from the query.
// Returns a *NotFoundError when no Dependency ID was found.
func (dq *DependencyQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = dq.Limit(1).IDs(setContextOp(ctx, dq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{dependency.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (dq *DependencyQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := dq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single Dependency entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one Dependency entity is found.
// Returns a *NotFoundError when no Dependency entities are found.
func (dq *DependencyQuery) Only(ctx context.Context) (*Dependency, error) {
	nodes, err := dq.Limit(2).All(setContextOp(ctx, dq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{dependency.Label}
	default:
		return nil, &NotSingularError{dependency.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (dq *DependencyQuery) OnlyX(ctx context.Context) *Dependency {
	node, err := dq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only Dependency ID in the query.
// Returns a *NotSingularError when more than one Dependency ID is found.
// Returns a *NotFoundError when no entities are found.
func (dq *DependencyQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = dq.Limit(2).IDs(setContextOp(ctx, dq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{dependency.Label}
	default:
		err = &NotSingularError{dependency.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (dq *DependencyQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := dq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of Dependencies.
func (dq *DependencyQuery) All(ctx context.Context) ([]*Dependency, error) {
	ctx = setContextOp(ctx, dq.ctx, "All")
	if err := dq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*Dependency, *DependencyQuery]()
	return withInterceptors[[]*Dependency](ctx, dq, qr, dq.inters)
}

// AllX is like All, but panics if an error occurs.
func (dq *DependencyQuery) AllX(ctx context.Context) []*Dependency {
	nodes, err := dq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of Dependency IDs.
func (dq *DependencyQuery) IDs(ctx context.Context) (ids []uuid.UUID, err error) {
	if dq.ctx.Unique == nil && dq.path != nil {
		dq.Unique(true)
	}
	ctx = setContextOp(ctx, dq.ctx, "IDs")
	if err = dq.Select(dependency.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (dq *DependencyQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := dq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (dq *DependencyQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, dq.ctx, "Count")
	if err := dq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, dq, querierCount[*DependencyQuery](), dq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (dq *DependencyQuery) CountX(ctx context.Context) int {
	count, err := dq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (dq *DependencyQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, dq.ctx, "Exist")
	switch _, err := dq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (dq *DependencyQuery) ExistX(ctx context.Context) bool {
	exist, err := dq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the DependencyQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (dq *DependencyQuery) Clone() *DependencyQuery {
	if dq == nil {
		return nil
	}
	return &DependencyQuery{
		config:                      dq.config,
		ctx:                         dq.ctx.Clone(),
		order:                       append([]dependency.OrderOption{}, dq.order...),
		inters:                      append([]Interceptor{}, dq.inters...),
		predicates:                  append([]predicate.Dependency{}, dq.predicates...),
		withPackage:                 dq.withPackage.Clone(),
		withDependentPackageName:    dq.withDependentPackageName.Clone(),
		withDependentPackageVersion: dq.withDependentPackageVersion.Clone(),
		withIncludedInSboms:         dq.withIncludedInSboms.Clone(),
		// clone intermediate query.
		sql:  dq.sql.Clone(),
		path: dq.path,
	}
}

// WithPackage tells the query-builder to eager-load the nodes that are connected to
// the "package" edge. The optional arguments are used to configure the query builder of the edge.
func (dq *DependencyQuery) WithPackage(opts ...func(*PackageVersionQuery)) *DependencyQuery {
	query := (&PackageVersionClient{config: dq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	dq.withPackage = query
	return dq
}

// WithDependentPackageName tells the query-builder to eager-load the nodes that are connected to
// the "dependent_package_name" edge. The optional arguments are used to configure the query builder of the edge.
func (dq *DependencyQuery) WithDependentPackageName(opts ...func(*PackageNameQuery)) *DependencyQuery {
	query := (&PackageNameClient{config: dq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	dq.withDependentPackageName = query
	return dq
}

// WithDependentPackageVersion tells the query-builder to eager-load the nodes that are connected to
// the "dependent_package_version" edge. The optional arguments are used to configure the query builder of the edge.
func (dq *DependencyQuery) WithDependentPackageVersion(opts ...func(*PackageVersionQuery)) *DependencyQuery {
	query := (&PackageVersionClient{config: dq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	dq.withDependentPackageVersion = query
	return dq
}

// WithIncludedInSboms tells the query-builder to eager-load the nodes that are connected to
// the "included_in_sboms" edge. The optional arguments are used to configure the query builder of the edge.
func (dq *DependencyQuery) WithIncludedInSboms(opts ...func(*BillOfMaterialsQuery)) *DependencyQuery {
	query := (&BillOfMaterialsClient{config: dq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	dq.withIncludedInSboms = query
	return dq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		PackageID uuid.UUID `json:"package_id,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.Dependency.Query().
//		GroupBy(dependency.FieldPackageID).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (dq *DependencyQuery) GroupBy(field string, fields ...string) *DependencyGroupBy {
	dq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &DependencyGroupBy{build: dq}
	grbuild.flds = &dq.ctx.Fields
	grbuild.label = dependency.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		PackageID uuid.UUID `json:"package_id,omitempty"`
//	}
//
//	client.Dependency.Query().
//		Select(dependency.FieldPackageID).
//		Scan(ctx, &v)
func (dq *DependencyQuery) Select(fields ...string) *DependencySelect {
	dq.ctx.Fields = append(dq.ctx.Fields, fields...)
	sbuild := &DependencySelect{DependencyQuery: dq}
	sbuild.label = dependency.Label
	sbuild.flds, sbuild.scan = &dq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a DependencySelect configured with the given aggregations.
func (dq *DependencyQuery) Aggregate(fns ...AggregateFunc) *DependencySelect {
	return dq.Select().Aggregate(fns...)
}

func (dq *DependencyQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range dq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, dq); err != nil {
				return err
			}
		}
	}
	for _, f := range dq.ctx.Fields {
		if !dependency.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if dq.path != nil {
		prev, err := dq.path(ctx)
		if err != nil {
			return err
		}
		dq.sql = prev
	}
	return nil
}

func (dq *DependencyQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*Dependency, error) {
	var (
		nodes       = []*Dependency{}
		_spec       = dq.querySpec()
		loadedTypes = [4]bool{
			dq.withPackage != nil,
			dq.withDependentPackageName != nil,
			dq.withDependentPackageVersion != nil,
			dq.withIncludedInSboms != nil,
		}
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*Dependency).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &Dependency{config: dq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	if len(dq.modifiers) > 0 {
		_spec.Modifiers = dq.modifiers
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, dq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := dq.withPackage; query != nil {
		if err := dq.loadPackage(ctx, query, nodes, nil,
			func(n *Dependency, e *PackageVersion) { n.Edges.Package = e }); err != nil {
			return nil, err
		}
	}
	if query := dq.withDependentPackageName; query != nil {
		if err := dq.loadDependentPackageName(ctx, query, nodes, nil,
			func(n *Dependency, e *PackageName) { n.Edges.DependentPackageName = e }); err != nil {
			return nil, err
		}
	}
	if query := dq.withDependentPackageVersion; query != nil {
		if err := dq.loadDependentPackageVersion(ctx, query, nodes, nil,
			func(n *Dependency, e *PackageVersion) { n.Edges.DependentPackageVersion = e }); err != nil {
			return nil, err
		}
	}
	if query := dq.withIncludedInSboms; query != nil {
		if err := dq.loadIncludedInSboms(ctx, query, nodes,
			func(n *Dependency) { n.Edges.IncludedInSboms = []*BillOfMaterials{} },
			func(n *Dependency, e *BillOfMaterials) { n.Edges.IncludedInSboms = append(n.Edges.IncludedInSboms, e) }); err != nil {
			return nil, err
		}
	}
	for name, query := range dq.withNamedIncludedInSboms {
		if err := dq.loadIncludedInSboms(ctx, query, nodes,
			func(n *Dependency) { n.appendNamedIncludedInSboms(name) },
			func(n *Dependency, e *BillOfMaterials) { n.appendNamedIncludedInSboms(name, e) }); err != nil {
			return nil, err
		}
	}
	for i := range dq.loadTotal {
		if err := dq.loadTotal[i](ctx, nodes); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (dq *DependencyQuery) loadPackage(ctx context.Context, query *PackageVersionQuery, nodes []*Dependency, init func(*Dependency), assign func(*Dependency, *PackageVersion)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*Dependency)
	for i := range nodes {
		fk := nodes[i].PackageID
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(packageversion.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "package_id" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (dq *DependencyQuery) loadDependentPackageName(ctx context.Context, query *PackageNameQuery, nodes []*Dependency, init func(*Dependency), assign func(*Dependency, *PackageName)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*Dependency)
	for i := range nodes {
		fk := nodes[i].DependentPackageNameID
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(packagename.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "dependent_package_name_id" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (dq *DependencyQuery) loadDependentPackageVersion(ctx context.Context, query *PackageVersionQuery, nodes []*Dependency, init func(*Dependency), assign func(*Dependency, *PackageVersion)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*Dependency)
	for i := range nodes {
		fk := nodes[i].DependentPackageVersionID
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(packageversion.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "dependent_package_version_id" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (dq *DependencyQuery) loadIncludedInSboms(ctx context.Context, query *BillOfMaterialsQuery, nodes []*Dependency, init func(*Dependency), assign func(*Dependency, *BillOfMaterials)) error {
	edgeIDs := make([]driver.Value, len(nodes))
	byID := make(map[uuid.UUID]*Dependency)
	nids := make(map[uuid.UUID]map[*Dependency]struct{})
	for i, node := range nodes {
		edgeIDs[i] = node.ID
		byID[node.ID] = node
		if init != nil {
			init(node)
		}
	}
	query.Where(func(s *sql.Selector) {
		joinT := sql.Table(dependency.IncludedInSbomsTable)
		s.Join(joinT).On(s.C(billofmaterials.FieldID), joinT.C(dependency.IncludedInSbomsPrimaryKey[0]))
		s.Where(sql.InValues(joinT.C(dependency.IncludedInSbomsPrimaryKey[1]), edgeIDs...))
		columns := s.SelectedColumns()
		s.Select(joinT.C(dependency.IncludedInSbomsPrimaryKey[1]))
		s.AppendSelect(columns...)
		s.SetDistinct(false)
	})
	if err := query.prepareQuery(ctx); err != nil {
		return err
	}
	qr := QuerierFunc(func(ctx context.Context, q Query) (Value, error) {
		return query.sqlAll(ctx, func(_ context.Context, spec *sqlgraph.QuerySpec) {
			assign := spec.Assign
			values := spec.ScanValues
			spec.ScanValues = func(columns []string) ([]any, error) {
				values, err := values(columns[1:])
				if err != nil {
					return nil, err
				}
				return append([]any{new(uuid.UUID)}, values...), nil
			}
			spec.Assign = func(columns []string, values []any) error {
				outValue := *values[0].(*uuid.UUID)
				inValue := *values[1].(*uuid.UUID)
				if nids[inValue] == nil {
					nids[inValue] = map[*Dependency]struct{}{byID[outValue]: {}}
					return assign(columns[1:], values[1:])
				}
				nids[inValue][byID[outValue]] = struct{}{}
				return nil
			}
		})
	})
	neighbors, err := withInterceptors[[]*BillOfMaterials](ctx, query, qr, query.inters)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected "included_in_sboms" node returned %v`, n.ID)
		}
		for kn := range nodes {
			assign(kn, n)
		}
	}
	return nil
}

func (dq *DependencyQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := dq.querySpec()
	if len(dq.modifiers) > 0 {
		_spec.Modifiers = dq.modifiers
	}
	_spec.Node.Columns = dq.ctx.Fields
	if len(dq.ctx.Fields) > 0 {
		_spec.Unique = dq.ctx.Unique != nil && *dq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, dq.driver, _spec)
}

func (dq *DependencyQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(dependency.Table, dependency.Columns, sqlgraph.NewFieldSpec(dependency.FieldID, field.TypeUUID))
	_spec.From = dq.sql
	if unique := dq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if dq.path != nil {
		_spec.Unique = true
	}
	if fields := dq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, dependency.FieldID)
		for i := range fields {
			if fields[i] != dependency.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
		if dq.withPackage != nil {
			_spec.Node.AddColumnOnce(dependency.FieldPackageID)
		}
		if dq.withDependentPackageName != nil {
			_spec.Node.AddColumnOnce(dependency.FieldDependentPackageNameID)
		}
		if dq.withDependentPackageVersion != nil {
			_spec.Node.AddColumnOnce(dependency.FieldDependentPackageVersionID)
		}
	}
	if ps := dq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := dq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := dq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := dq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (dq *DependencyQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(dq.driver.Dialect())
	t1 := builder.Table(dependency.Table)
	columns := dq.ctx.Fields
	if len(columns) == 0 {
		columns = dependency.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if dq.sql != nil {
		selector = dq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if dq.ctx.Unique != nil && *dq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range dq.predicates {
		p(selector)
	}
	for _, p := range dq.order {
		p(selector)
	}
	if offset := dq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := dq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// WithNamedIncludedInSboms tells the query-builder to eager-load the nodes that are connected to the "included_in_sboms"
// edge with the given name. The optional arguments are used to configure the query builder of the edge.
func (dq *DependencyQuery) WithNamedIncludedInSboms(name string, opts ...func(*BillOfMaterialsQuery)) *DependencyQuery {
	query := (&BillOfMaterialsClient{config: dq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	if dq.withNamedIncludedInSboms == nil {
		dq.withNamedIncludedInSboms = make(map[string]*BillOfMaterialsQuery)
	}
	dq.withNamedIncludedInSboms[name] = query
	return dq
}

// DependencyGroupBy is the group-by builder for Dependency entities.
type DependencyGroupBy struct {
	selector
	build *DependencyQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (dgb *DependencyGroupBy) Aggregate(fns ...AggregateFunc) *DependencyGroupBy {
	dgb.fns = append(dgb.fns, fns...)
	return dgb
}

// Scan applies the selector query and scans the result into the given value.
func (dgb *DependencyGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, dgb.build.ctx, "GroupBy")
	if err := dgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*DependencyQuery, *DependencyGroupBy](ctx, dgb.build, dgb, dgb.build.inters, v)
}

func (dgb *DependencyGroupBy) sqlScan(ctx context.Context, root *DependencyQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(dgb.fns))
	for _, fn := range dgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*dgb.flds)+len(dgb.fns))
		for _, f := range *dgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*dgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := dgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// DependencySelect is the builder for selecting fields of Dependency entities.
type DependencySelect struct {
	*DependencyQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (ds *DependencySelect) Aggregate(fns ...AggregateFunc) *DependencySelect {
	ds.fns = append(ds.fns, fns...)
	return ds
}

// Scan applies the selector query and scans the result into the given value.
func (ds *DependencySelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, ds.ctx, "Select")
	if err := ds.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*DependencyQuery, *DependencySelect](ctx, ds.DependencyQuery, ds, ds.inters, v)
}

func (ds *DependencySelect) sqlScan(ctx context.Context, root *DependencyQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(ds.fns))
	for _, fn := range ds.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*ds.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := ds.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
