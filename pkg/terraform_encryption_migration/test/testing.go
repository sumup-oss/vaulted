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
	"crypto/rsa"

	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/stretchr/testify/mock"

	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/ini"
	"github.com/sumup-oss/vaulted/pkg/terraform"
	"github.com/sumup-oss/vaulted/pkg/terraform_encryption_migration"
)

type MockTerraformEncryptionMigrationService struct {
	mock.Mock
}

func (m *MockTerraformEncryptionMigrationService) ConvertIniContentToLegacyTerraformContent(
	passphraseLength int,
	iniContent *ini.Content,
	pubKey *rsa.PublicKey,
	encryptedPassphraseSvc terraform_encryption_migration.EncryptedPassphraseService,
	encryptedContentSvc terraform_encryption_migration.EncryptedContentService,
) (*terraform.Content, error) {
	args := m.Called(passphraseLength, iniContent, pubKey, encryptedPassphraseSvc, encryptedContentSvc)
	returnValue := args.Get(0)
	err := args.Error(1)
	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*terraform.Content), nil
}

func (m *MockTerraformEncryptionMigrationService) ConvertIniContentToV1TerraformContent(
	passphraseLength int,
	iniContent *ini.Content,
	pubKey *rsa.PublicKey,
	encryptedPassphraseSvc terraform_encryption_migration.EncryptedPassphraseService,
	encryptedPayloadSvc terraform_encryption_migration.EncryptedPayloadService,
) (*terraform.Content, error) {
	args := m.Called(passphraseLength, iniContent, pubKey, encryptedPassphraseSvc, encryptedPayloadSvc)
	returnValue := args.Get(0)
	err := args.Error(1)
	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*terraform.Content), nil
}

func (m *MockTerraformEncryptionMigrationService) MigrateEncryptedTerraformResourceHcl(
	hclParser hcl.Parser,
	hclBytes []byte,
	privKey *rsa.PrivateKey,
	pubKey *rsa.PublicKey,
	legacyEncryptedContentSvc terraform_encryption_migration.EncryptedContentService,
	encryptedPassphraseSvc terraform_encryption_migration.EncryptedPassphraseService,
	encryptedPayloadSvc terraform_encryption_migration.EncryptedPayloadService,
) (*ast.File, error) {
	args := m.Called(
		hclParser,
		hclBytes,
		privKey,
		pubKey,
		legacyEncryptedContentSvc,
		encryptedPassphraseSvc,
		encryptedPayloadSvc,
	)
	returnValue := args.Get(0)
	err := args.Error(1)
	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*ast.File), nil
}

func (m *MockTerraformEncryptionMigrationService) RotateOrRekeyEncryptedTerraformResourceHcl(
	hclParser hcl.Parser,
	hclBytes []byte,
	privKey *rsa.PrivateKey,
	pubKey *rsa.PublicKey,
	encryptedPassphraseSvc terraform_encryption_migration.EncryptedPassphraseService,
	encryptedPayloadSvc terraform_encryption_migration.EncryptedPayloadService,
) (*ast.File, error) {
	args := m.Called(
		hclParser,
		hclBytes,
		privKey,
		pubKey,
		encryptedPassphraseSvc,
		encryptedPayloadSvc,
	)
	returnValue := args.Get(0)
	err := args.Error(1)
	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*ast.File), nil
}
