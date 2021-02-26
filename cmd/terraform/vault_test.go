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

package terraform

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/sumup-oss/go-pkgs/os/ostest"
	gopkgsTestUtils "github.com/sumup-oss/go-pkgs/testutils"
	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/ini"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/rsa"
	"github.com/sumup-oss/vaulted/pkg/terraform"
	"github.com/sumup-oss/vaulted/pkg/terraform_encryption_migration"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

func TestNewVaultCmd(t *testing.T) {
	t.Parallel()

	osExecutor := ostest.NewFakeOsExecutor(t)
	b64Svc := base64.NewBase64Service()
	rsaSvc := rsa.NewRsaService(osExecutor)
	aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())
	encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)
	legacyEncContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)
	encContentSvc := content.NewV1EncryptedContentService(b64Svc, aesSvc)
	encPayloadSvc := payload.NewEncryptedPayloadService(
		header.NewHeaderService(),
		encPassphraseSvc,
		encContentSvc,
	)
	hclSvc := hcl.NewHclService()
	tfSvc := terraform.NewTerraformService()
	tfEncMigrationSvc := terraform_encryption_migration.NewTerraformEncryptionMigrationService(tfSvc)

	actual := NewVaultCmd(
		osExecutor,
		rsaSvc,
		ini.NewIniService(),
		encPassphraseSvc,
		legacyEncContentSvc,
		encPayloadSvc,
		hclSvc,
		tfEncMigrationSvc,
	)

	assert.Equal(t, "vault", actual.Use)
	assert.Equal(t, "github.com/sumup-oss/terraform-provider-vaulted resources related commands", actual.Short)
	assert.Equal(t, "github.com/sumup-oss/terraform-provider-vaulted resources related commands", actual.Long)
}

func TestVaultCmd_Execute(t *testing.T) {
	t.Parallel()

	outputBuff := &bytes.Buffer{}

	osExecutor := ostest.NewFakeOsExecutor(t)
	b64Svc := base64.NewBase64Service()
	rsaSvc := rsa.NewRsaService(osExecutor)
	aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())
	encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)
	encContentSvc := content.NewV1EncryptedContentService(b64Svc, aesSvc)
	encPayloadSvc := payload.NewEncryptedPayloadService(
		header.NewHeaderService(),
		encPassphraseSvc,
		encContentSvc,
	)
	hclSvc := hcl.NewHclService()
	tfSvc := terraform.NewTerraformService()
	legacyEncContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)
	tfEncMigrationSvc := terraform_encryption_migration.NewTerraformEncryptionMigrationService(tfSvc)

	cmdInstance := NewVaultCmd(
		osExecutor,
		rsaSvc,
		ini.NewIniService(),
		encPassphraseSvc,
		legacyEncContentSvc,
		encPayloadSvc,
		hclSvc,
		tfEncMigrationSvc,
	)

	_, err := gopkgsTestUtils.RunCommandInSameProcess(
		cmdInstance,
		[]string{},
		outputBuff,
	)

	assert.Equal(
		t,
		`github.com/sumup-oss/terraform-provider-vaulted resources related commands

Usage:
  vault [flags]
  vault [command]

Available Commands:
  help         Help about any command
  ini          Convert an INI file to Terraform file
  migrate      Reads terraform resources file and migrates them to new encryption format
  new-resource Create new terraform vaulted vault secret resource
  rekey        Rekey (decrypt and encrypt using different keypair) existing terraform resources
  rotate       Rotate (decrypt and encrypt) existing terraform resources

Flags:
  -h, --help   help for vault

Use "vault [command] --help" for more information about a command.
`,
		outputBuff.String(),
	)
	assert.Nil(t, err)

	osExecutor.AssertExpectations(t)
}
