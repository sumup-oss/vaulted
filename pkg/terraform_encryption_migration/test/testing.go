// Copyright 2018 SumUp Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package test

import (
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/stretchr/testify/mock"

	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/terraform_encryption_migration"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

type MockTerraformEncryptionMigrationService struct {
	mock.Mock
}

func (m *MockTerraformEncryptionMigrationService) RotateOrRekeyEncryptedTerraformResourceHcl(
	hclParser hcl.Parser,
	hclBytes []byte,
	passphraseSvc *passphrase.Service,
	payloadSerdeSvc *payload.SerdeService,
	oldPayloadDecrypter terraform_encryption_migration.PayloadDecrypter,
	newPayloadEncrypter terraform_encryption_migration.PayloadEncrypter,
) (*ast.File, error) {
	args := m.Called(
		hclParser,
		hclBytes,
		passphraseSvc,
		payloadSerdeSvc,
		oldPayloadDecrypter,
		newPayloadEncrypter,
	)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*ast.File), nil
}
