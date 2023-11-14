//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package neo4j

import (
	"context"
	"strings"

	"github.com/apache/age/drivers/golang/age"
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type ageClient struct {
	ag *age.Age
}

func init() {
	backends.Register("age", getBackend)
}

func getBackend(_ context.Context, args backends.BackendArgs) (backends.Backend, error) {
	// var dsn string = "host={host} port={port} dbname={dbname} user={username} password={password} sslmode=disable"
	var dsn string = "host=127.0.0.1 port=5432 dbname=postgres user=postgresuser password=postgresPW sslmode=disable"

	// var graphName string = "{graph_path}"
	var graphName string = "testGraph"

	ag, err := age.ConnectAge(graphName, dsn)
	if err != nil {
		panic(err)
	}

	client := &ageClient{ag}
	return client, nil
}

func matchProperties(sb *strings.Builder, firstMatch bool, label, property string, resolver string) {
	if firstMatch {
		sb.WriteString(" WHERE ")
	} else {
		sb.WriteString(" AND ")
	}
	sb.WriteString(label)
	sb.WriteString(".")
	sb.WriteString(property)
	sb.WriteString(" = ")
	sb.WriteString(resolver)
}

func (c *ageClient) Licenses(ctx context.Context, licenseSpec *model.LicenseSpec) ([]*model.License, error) {
	return nil, nil
}
func (c *ageClient) IngestLicense(ctx context.Context, license *model.LicenseInputSpec) (*model.License, error) {
	return nil, nil
}
func (c *ageClient) IngestLicenses(ctx context.Context, licenses []*model.LicenseInputSpec) ([]*model.License, error) {
	return nil, nil
}
func (c *ageClient) CertifyLegal(ctx context.Context, certifyLegalSpec *model.CertifyLegalSpec) ([]*model.CertifyLegal, error) {
	return nil, nil
}
func (c *ageClient) IngestCertifyLegal(ctx context.Context, subject model.PackageOrSourceInput, declaredLicenses []*model.LicenseInputSpec, discoveredLicenses []*model.LicenseInputSpec, certifyLegal *model.CertifyLegalInputSpec) (*model.CertifyLegal, error) {
	return nil, nil
}
func (c *ageClient) IngestCertifyLegals(ctx context.Context, subjects model.PackageOrSourceInputs, declaredLicensesList [][]*model.LicenseInputSpec, discoveredLicensesList [][]*model.LicenseInputSpec, certifyLegals []*model.CertifyLegalInputSpec) ([]*model.CertifyLegal, error) {
	return nil, nil
}
