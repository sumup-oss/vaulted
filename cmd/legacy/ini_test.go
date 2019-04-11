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

package legacy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/sumup-oss/go-pkgs/os/ostest"
	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/ini"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/rsa"
	"github.com/sumup-oss/vaulted/pkg/terraform"
	"github.com/sumup-oss/vaulted/pkg/terraform_encryption_migration"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
)

func TestNewIniCommand(t *testing.T) {
	t.Parallel()

	osExecutor := ostest.NewFakeOsExecutor(t)
	iniSvc := ini.NewIniService()
	b64Svc := base64.NewBase64Service()
	rsaSvc := rsa.NewRsaService(osExecutor)
	aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

	encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)
	encContentSvc := content.NewV1EncryptedContentService(b64Svc, aesSvc)
	hclSvc := hcl.NewHclService()
	tfSvc := terraform.NewTerraformService()
	tfEncMigrationSvc := terraform_encryption_migration.NewTerraformEncryptionMigrationService(tfSvc)

	actual := NewIniCommand(
		osExecutor,
		rsaSvc,
		iniSvc,
		encPassphraseSvc,
		encContentSvc,
		hclSvc,
		tfSvc,
		tfEncMigrationSvc,
	)

	assert.Equal(
		t,
		"ini --public-key-path ./my-key.pem --in ./secrets.ini --out ./secrets.tf",
		actual.Use,
	)

	assert.Equal(
		t,
		"Convert an INI file to Terraform file",
		actual.Short,
	)

	assert.Equal(
		t,
		"Convert an INI file to Terraform file with vault_encrypted_secret resources,"+
			" encrypted with AES128-CBC symmetric encryption. "+
			"Passfile is random generated during runtime and encrypted with RSA asymmetric keypair.",
		actual.Long,
	)

	publicKeyPathFlag := actual.Flag("public-key-path")

	assert.NotNil(t, publicKeyPathFlag)
	assert.Equal(
		t,
		"Path to RSA public key used to encrypt runtime random generated passphrase.",
		publicKeyPathFlag.Usage,
	)

	inPathFlag := actual.Flag("in")

	assert.NotNil(t, inPathFlag)
	assert.Equal(t, "Path to the input INI file", inPathFlag.Usage)

	outPathFlag := actual.Flag("out")

	assert.NotNil(t, outPathFlag)
	assert.Equal(t, "Path to the output terraform file", outPathFlag.Usage)
}
