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

package vault

import (
	"bytes"
	"crypto/rand"
	stdRsa "crypto/rsa"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/sumup-oss/vaulted/pkg/ini"
	"github.com/sumup-oss/vaulted/pkg/terraform_encryption_migration"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sumup-oss/go-pkgs/os"
	"github.com/sumup-oss/go-pkgs/os/ostest"
	"github.com/sumup-oss/go-pkgs/testutils"
	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/rsa"
	"github.com/sumup-oss/vaulted/pkg/terraform"
	vaultedTestUtils "github.com/sumup-oss/vaulted/pkg/testutils"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

func TestIniCmd_Execute(t *testing.T) {
	t.Run(
		"with no arguments, it returns error",
		func(t *testing.T) {
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
			tfEncMigrationSvc := terraform_encryption_migration.NewTerraformEncryptionMigrationService(
				tfSvc,
			)
			iniSvc := ini.NewIniService()

			cmdInstance := NewIniCommand(
				osExecutor,
				rsaSvc,
				iniSvc,
				encPassphraseSvc,
				encPayloadSvc,
				hclSvc,
				tfEncMigrationSvc,
			)

			_, err := testutils.RunCommandInSameProcess(
				cmdInstance,
				[]string{},
				outputBuff,
			)

			assert.Equal(
				t,
				`required flag(s) "in", "out", "public-key-path" not set`,
				err.Error(),
			)
		},
	)

	t.Run(
		"with 'public-key-path', 'in' and 'out' flags specified "+
			"it writes migrated terraform resources at `out`",
		func(t *testing.T) {
			tmpDir := testutils.TestCwd(t, "vaulted")

			realOsExecutor := &os.RealOsExecutor{}

			iniContent := []byte(`[sectionExample]
myKey=example

[sectionExampleAgain]
myOtherKey=exampleother
`)
			inPathFlag := filepath.Join(tmpDir, "in.ini")

			err := realOsExecutor.WriteFile(inPathFlag, iniContent, 0644)
			require.Nil(t, err)

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			pubkeyPath := testutils.GenerateAndWritePublicKey(t, tmpDir, "key.pub", privKey)

			rsaSvc := rsa.NewRsaService(realOsExecutor)
			b64Svc := base64.NewBase64Service()

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())
			encContentSvc := content.NewV1EncryptedContentService(b64Svc, aesSvc)
			encPayloadSvc := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encPassphraseSvc,
				encContentSvc,
			)
			hclSvc := hcl.NewHclService()
			tfSvc := terraform.NewTerraformService()
			iniSvc := ini.NewIniService()
			tfEncMigrationSvc := terraform_encryption_migration.NewTerraformEncryptionMigrationService(
				tfSvc,
			)

			outPathFlag := filepath.Join(tmpDir, "out.tf")
			cmdInstance := NewIniCommand(
				realOsExecutor,
				rsaSvc,
				iniSvc,
				encPassphraseSvc,
				encPayloadSvc,
				hclSvc,
				tfEncMigrationSvc,
			)

			cmdArgs := []string{
				fmt.Sprintf("--public-key-path=%s", pubkeyPath),
				fmt.Sprintf("--in=%s", inPathFlag),
				fmt.Sprintf("--out=%s", outPathFlag),
			}

			var outputBuff bytes.Buffer
			_, err = testutils.RunCommandInSameProcess(
				cmdInstance,
				cmdArgs,
				&outputBuff,
			)
			require.Nil(t, err)
			assert.Equal(t, "", outputBuff.String())

			outContent, err := realOsExecutor.ReadFile(outPathFlag)
			require.Nil(t, err)

			regexMatches := vaultedTestUtils.NewTerraformRegex.FindAllStringSubmatch(
				string(outContent),
				-1,
			)
			require.Equal(t, 2, len(regexMatches))

			assert.Equal(
				t,
				"vaulted_vault_secret_sectionExampleAgain_myOtherKey",
				regexMatches[0][1],
			)
			assert.Equal(
				t,
				"secret/sectionExampleAgain/myOtherKey",
				regexMatches[0][2],
			)
			assert.NotEqual(
				t,
				"",
				regexMatches[0][3],
			)

			assert.Equal(
				t,
				"vaulted_vault_secret_sectionExample_myKey",
				regexMatches[1][1],
			)
			assert.Equal(
				t,
				"secret/sectionExample/myKey",
				regexMatches[1][2],
			)
			assert.NotEqual(
				t,
				"",
				regexMatches[1][3],
			)
		},
	)
}
