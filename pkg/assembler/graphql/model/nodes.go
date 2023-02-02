// Code generated by github.com/99designs/gqlgen, DO NOT EDIT.

package model

// Package represents a package.
//
// In the pURL representation, each Package matches a `pkg:<type>` partial pURL.
// The `type` field matches the pURL types but we might also use `"guac"` for the
// cases where the pURL representation is not complete or when we have custom
// rules.
//
// This node is a singleton: backends guarantee that there is exactly one node with
// the same `type` value.
//
// Also note that this is named `Package`, not `PackageType`. This is only to make
// queries more readable.
type Package struct {
	Type       string              `json:"type"`
	Namespaces []*PackageNamespace `json:"namespaces"`
}

// PackageName is a name for packages.
//
// In the pURL representation, each PackageName matches the
// `pkg:<type>/<namespace>/<name>` pURL.
//
// Names are always mandatory.
//
// This is the first node in the trie that can be referred to by other parts of
// GUAC.
type PackageName struct {
	Name     string            `json:"name"`
	Versions []*PackageVersion `json:"versions"`
}

// PackageNamespace is a namespace for packages.
//
// In the pURL representation, each PackageNamespace matches the
// `pkg:<type>/<namespace>/` partial pURL.
//
// Namespaces are optional and type specific. Because they are optional, we use
// empty string to denote missing namespaces.
type PackageNamespace struct {
	Namespace string         `json:"namespace"`
	Names     []*PackageName `json:"names"`
}

// PackageQualifier is a qualifier for a package, a key-value pair.
//
// In the pURL representation, it is a part of the `<qualifiers>` part of the
// `pkg:<type>/<namespace>/<name>@<version>?<qualifiers>` pURL.
//
// Qualifiers are optional, each Package type defines own rules for handling them,
// and multiple qualifiers could be attached to the same package.
//
// This node cannot be directly referred by other parts of GUAC.
type PackageQualifier struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// PackageQualifierInput is the same as PackageQualifier, but usable as query
// input.
//
// GraphQL does not allow input types to contain composite types and does not allow
// composite types to contain input types. So, although in this case these two
// types are semantically the same, we have to duplicate the definition.
//
// Keys are mandatory, but values could also be `null` if we want to match all
// values for a specific key.
//
// TODO(mihaimaruseac): Formalize empty vs null when the schema is fully done
type PackageQualifierInput struct {
	Key   string  `json:"key"`
	Value *string `json:"value"`
}

// PackageVersion is a package version.
//
// In the pURL representation, each PackageName matches the
// `pkg:<type>/<namespace>/<name>@<version>` pURL.
//
// Versions are optional and each Package type defines own rules for handling them.
// For this level of GUAC, these are just opaque strings.
//
// This node can be referred to by other parts of GUAC.
//
// Subpath and qualifiers are optional. Lack of qualifiers is represented by an
// empty list and lack of subpath by empty string (to be consistent with
// optionality of namespace and version). Two nodes that have different qualifiers
// and/or subpath but the same version mean two different packages in the trie
// (they are different). Two nodes that have same version but qualifiers of one are
// a subset of the qualifier of the other also mean two different packages in the
// trie.
type PackageVersion struct {
	Version    string              `json:"version"`
	Qualifiers []*PackageQualifier `json:"qualifiers"`
	Subpath    string              `json:"subpath"`
}

// PkgSpec allows filtering the list of packages to return.
//
// Each field matches a qualifier from pURL. Use `null` to match on all values at
// that level. For example, to get all packages in GUAC backend, use a PkgSpec
// where every field is `null`.
//
// Empty string at a field means matching with the empty string. If passing in
// qualifiers, all of the values in the list must match. Since we want to return
// nodes with any number of qualifiers if no qualifiers are passed in the input, we
// must also return the same set of nodes it the qualifiers list is empty. To match
// on nodes that don't contain any qualifier, set `matchOnlyEmptyQualifiers` to
// true. If this field is true, then the qualifiers argument is ignored.
type PkgSpec struct {
	Type                     *string                  `json:"type"`
	Namespace                *string                  `json:"namespace"`
	Name                     *string                  `json:"name"`
	Version                  *string                  `json:"version"`
	Qualifiers               []*PackageQualifierInput `json:"qualifiers"`
	MatchOnlyEmptyQualifiers *bool                    `json:"matchOnlyEmptyQualifiers"`
	Subpath                  *string                  `json:"subpath"`
}

// Source represents a source.
//
// This can be the version control system that is being used.
//
// This node is a singleton: backends guarantee that there is exactly one node with
// the same `type` value.
//
// Also note that this is named `Source`, not `SourceType`. This is only to make
// queries more readable.
type Source struct {
	Type       string             `json:"type"`
	Namespaces []*SourceNamespace `json:"namespaces"`
}

// SourceName is a url of the repository.
//
// SourceName is mandatory.
//
// This is the first node in the trie that can be referred to by other parts of
// GUAC.
type SourceName struct {
	Name       string             `json:"name"`
	Qualifiers []*SourceQualifier `json:"qualifiers"`
}

// SourceNamespace is a namespace for sources.
//
// This can be represented as the location of the repo (such as github/gitlab/bitbucket)
//
// Namespaces are optional and type specific. Because they are optional, we use
// empty string to denote missing namespaces.
type SourceNamespace struct {
	Namespace string        `json:"namespace"`
	Names     []*SourceName `json:"names"`
}

// SourceQualifier containers the commit or tag.
//
// Either a tag or commit needs to be specified.
//
// This node can be referred to by other parts of GUAC.
type SourceQualifier struct {
	Tag    string `json:"tag"`
	Commit string `json:"commit"`
}

// SourceQualifierInput is the same as SourceQualifier, but usable as query
// input.
type SourceQualifierInput struct {
	Tag    *string `json:"tag"`
	Commit *string `json:"commit"`
}

// PkgSpec allows filtering the list of packages to return.
//
// Each field matches a qualifier from pURL. Use `null` to match on all values at
// that level. For example, to get all packages in GUAC backend, use a PkgSpec
// where every field is `null`.
//
// Empty string at a field means matching with the empty string.
type SourceSpec struct {
	Type      *string               `json:"type"`
	Namespace *string               `json:"namespace"`
	Name      *string               `json:"name"`
	Qualifier *SourceQualifierInput `json:"qualifier"`
}
