package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.45

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// IngestDependency is the resolver for the ingestDependency field.
func (r *mutationResolver) IngestDependency(ctx context.Context, pkg model.IDorPkgInput, depPkg model.IDorPkgInput, depPkgMatchType model.MatchFlags, dependency model.IsDependencyInputSpec) (string, error) {
	funcName := "IngestDependency"
	if !dependency.DependencyType.IsValid() {
		return "", gqlerror.Errorf("%v :: dependency type was not valid", funcName)
	}

	return r.Backend.IngestDependency(ctx, pkg, depPkg, depPkgMatchType, dependency)
}

// IngestDependencies is the resolver for the ingestDependencies field.
func (r *mutationResolver) IngestDependencies(ctx context.Context, pkgs []*model.IDorPkgInput, depPkgs []*model.IDorPkgInput, depPkgMatchType model.MatchFlags, dependencies []*model.IsDependencyInputSpec) ([]string, error) {
	funcName := "IngestDependencies"
	ingestedDependenciesIDS := []string{}
	if len(pkgs) != len(depPkgs) {
		return ingestedDependenciesIDS, gqlerror.Errorf("%v :: uneven packages and dependent packages for ingestion", funcName)
	}
	if len(pkgs) != len(dependencies) {
		return ingestedDependenciesIDS, gqlerror.Errorf("%v :: uneven packages and dependencies nodes for ingestion", funcName)
	}
	for _, dependency := range dependencies {
		if dependency != nil && !dependency.DependencyType.IsValid() {
			return ingestedDependenciesIDS, gqlerror.Errorf("%v :: not all dependencies had valid types", funcName)
		}
	}

	return r.Backend.IngestDependencies(ctx, pkgs, depPkgs, depPkgMatchType, dependencies)
}

// IsDependency is the resolver for the IsDependency field.
func (r *queryResolver) IsDependency(ctx context.Context, isDependencySpec model.IsDependencySpec) ([]*model.IsDependency, error) {
	funcName := "IsDependency"
	if isDependencySpec.DependencyType != nil && !isDependencySpec.DependencyType.IsValid() {
		return nil, gqlerror.Errorf("%s :: dependency type was not valid", funcName)
	}

	return r.Backend.IsDependency(ctx, &isDependencySpec)
}

// IsDependencyList is the resolver for the IsDependencyList field.
func (r *queryResolver) IsDependencyList(ctx context.Context, isDependencySpec model.IsDependencySpec, after *string, first *int) (*model.IsDependencyConnection, error) {
	funcName := "IsDependency"
	if isDependencySpec.DependencyType != nil && !isDependencySpec.DependencyType.IsValid() {
		return nil, gqlerror.Errorf("%s :: dependency type was not valid", funcName)
	}

	return r.Backend.IsDependencyList(ctx, isDependencySpec, after, first)
}
