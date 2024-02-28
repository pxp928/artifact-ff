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

package backend

import (
	"context"
	"crypto/sha256"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/license"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) IngestLicenses(ctx context.Context, licenses []*model.IDorLicenseInput) ([]string, error) {
	funcName := "IngestLicenses"
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkLicense(ctx, client, licenses)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	return *ids, nil
}

func (b *EntBackend) IngestLicense(ctx context.Context, license *model.IDorLicenseInput) (string, error) {
	record, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		client := ent.TxFromContext(ctx)
		licenseID, err := upsertLicense(ctx, client, *license.LicenseInput)
		if err != nil {
			return nil, err
		}

		return licenseID, nil
	})
	if err != nil {
		return "", err
	}

	return *record, nil
}

func (b *EntBackend) Licenses(ctx context.Context, filter *model.LicenseSpec) ([]*model.License, error) {
	records, err := getLicenses(ctx, b.client, *filter)
	if err != nil {
		return nil, err
	}
	return collect(records, toModelLicense), nil
}

func getLicenses(ctx context.Context, client *ent.Client, filter model.LicenseSpec) ([]*ent.License, error) {
	results, err := client.License.Query().
		Where(licenseQuery(filter)).
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, err
	}
	return results, nil
}

func upsertBulkLicense(ctx context.Context, tx *ent.Tx, licenseInputs []*model.IDorLicenseInput) (*[]string, error) {
	batches := chunk(licenseInputs, 100)
	ids := make([]string, 0)

	for _, licenses := range batches {
		creates := make([]*ent.LicenseCreate, len(licenses))
		for i, lic := range licenses {
			l := lic
			licenseID := uuid.NewHash(sha256.New(), uuid.NameSpaceDNS, []byte(helpers.GetKey[*model.LicenseInputSpec, string](l.LicenseInput, helpers.LicenseServerKey)), 5)
			creates[i] = generateLicenseCreate(tx, &licenseID, l.LicenseInput)
			ids = append(ids, licenseID.String())
		}

		err := tx.License.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(
					license.FieldName,
					license.FieldInline,
					license.FieldListVersion,
				),
			).
			Ignore().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert license node")
		}
	}

	return &ids, nil
}

func generateLicenseCreate(tx *ent.Tx, licenseID *uuid.UUID, licInput *model.LicenseInputSpec) *ent.LicenseCreate {
	return tx.License.Create().
		SetID(*licenseID).
		SetName(licInput.Name).
		SetInline(stringOrEmpty(licInput.Inline)).
		SetListVersion(stringOrEmpty(licInput.ListVersion))
}

func upsertLicense(ctx context.Context, tx *ent.Tx, spec model.LicenseInputSpec) (*string, error) {
	licenseID := uuid.NewHash(sha256.New(), uuid.NameSpaceDNS, []byte(helpers.GetKey[*model.LicenseInputSpec, string](&spec, helpers.LicenseServerKey)), 5)
	insert := generateLicenseCreate(tx, &licenseID, &spec)
	_, err := insert.
		OnConflict(
			sql.ConflictColumns(
				license.FieldName,
				license.FieldInline,
				license.FieldListVersion,
			),
		).
		Ignore().
		ID(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "upsert license node")
	}
	return ptrfrom.String(licenseID.String()), nil
}

func licenseQuery(filter model.LicenseSpec) predicate.License {
	return license.And(
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Name, license.NameEqualFold),
		optionalPredicate(filter.Inline, license.InlineEqualFold),
		optionalPredicate(filter.ListVersion, license.ListVersionEqualFold),
	)
}

func licenseInputQuery(filter model.LicenseInputSpec) predicate.License {
	return licenseQuery(model.LicenseSpec{
		Name:        &filter.Name,
		Inline:      filter.Inline,
		ListVersion: filter.ListVersion,
	})
}

func getLicenseID(ctx context.Context, client *ent.Client, license model.LicenseInputSpec) (uuid.UUID, error) {
	return client.License.Query().Where(licenseInputQuery(license)).OnlyID(ctx)
}
