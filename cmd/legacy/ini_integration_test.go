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
	"bytes"
	"crypto/rand"
	stdRsa "crypto/rsa"
	"errors"
	"fmt"
	stdOs "os"
	"path/filepath"
	"testing"

	goIni "github.com/go-ini/ini"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/sumup-oss/go-pkgs/os"
	"github.com/sumup-oss/go-pkgs/os/ostest"
	"github.com/sumup-oss/go-pkgs/testutils"
	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/ini"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/rsa"
	testRsa "github.com/sumup-oss/vaulted/pkg/rsa/test"
	"github.com/sumup-oss/vaulted/pkg/terraform"
	"github.com/sumup-oss/vaulted/pkg/terraform/test"
	"github.com/sumup-oss/vaulted/pkg/terraform_encryption_migration"
	testTfEncMigration "github.com/sumup-oss/vaulted/pkg/terraform_encryption_migration/test"
	vaultedTestUtils "github.com/sumup-oss/vaulted/pkg/testutils"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
)

type mockIniService struct {
	mock.Mock
}

func (m *mockIniService) ReadIniAtPath(path string) (*goIni.File, error) {
	args := m.Called(path)
	returnValue := args.Get(0)
	err := args.Error(1)
	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*goIni.File), err
}

func (m *mockIniService) ParseIniFileContents(file *goIni.File) *ini.Content {
	args := m.Called(file)
	returnValue := args.Get(0)
	if returnValue == nil {
		return nil
	}

	return returnValue.(*ini.Content)
}

func TestIniCommand_Execute(t *testing.T) {
	t.Run(
		"with no arguments, it returns error",
		func(t *testing.T) {
			outputBuff := &bytes.Buffer{}

			osExecutor := ostest.NewFakeOsExecutor(t)

			iniSvc := ini.NewIniService()
			b64Svc := base64.NewBase64Service()
			rsaSvc := rsa.NewRsaService(osExecutor)
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)
			encContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)
			hclSvc := hcl.NewHclService()
			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := terraform_encryption_migration.NewTerraformEncryptionMigrationService(
				tfSvc,
			)

			cmdInstance := NewIniCommand(
				osExecutor,
				rsaSvc,
				iniSvc,
				encPassphraseSvc,
				encContentSvc,
				hclSvc,
				tfSvc,
				tfEncMigrationSvc,
			)

			_, err := testutils.RunCommandInSameProcess(
				cmdInstance,
				[]string{},
				outputBuff,
			)

			expectedOutput := `Error: required flag(s) "in", "out", "public-key-path" not set
Usage:
  ini --public-key-path ./my-key.pem --in ./secrets.ini --out ./secrets.tf [flags]

Flags:
  -h, --help                     help for ini
      --in string                Path to the input INI file
      --out string               Path to the output terraform file
      --public-key-path string   Path to RSA public key used to encrypt runtime random generated passphrase.

`
			assert.Equal(t, expectedOutput, outputBuff.String())
			assert.Equal(
				t,
				`required flag(s) "in", "out", "public-key-path" not set`,
				err.Error(),
			)

			osExecutor.AssertExpectations(t)
		},
	)

	t.Run(
		"with 'public-key-path', 'in', 'out' flags specified, but reading the 'public-key-path' fails, "+
			"it returns error",
		func(t *testing.T) {
			publicKeyPathFlag := "/tmp/example.pub"

			outputBuff := &bytes.Buffer{}
			osExecutor := ostest.NewFakeOsExecutor(t)

			fakeError := errors.New("readpublickeyfrompathError")
			rsaSvc := &testRsa.MockRsaService{}
			rsaSvc.On(
				"ReadPublicKeyFromPath",
				publicKeyPathFlag,
			).Return(nil, fakeError)

			iniSvc := ini.NewIniService()
			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)
			encContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)
			hclSvc := hcl.NewHclService()
			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := terraform_encryption_migration.NewTerraformEncryptionMigrationService(
				tfSvc,
			)

			cmdInstance := NewIniCommand(
				osExecutor,
				rsaSvc,
				iniSvc,
				encPassphraseSvc,
				encContentSvc,
				hclSvc,
				tfSvc,
				tfEncMigrationSvc,
			)

			cmdArgs := []string{
				fmt.Sprintf("--public-key-path=%s", publicKeyPathFlag),
				"--in=/tmp/example.in",
				"--out=/tmp/example.out",
			}

			_, err := testutils.RunCommandInSameProcess(
				cmdInstance,
				cmdArgs,
				outputBuff,
			)

			assert.Contains(t, err.Error(), "failed to read specified public key")

			osExecutor.AssertExpectations(t)
			rsaSvc.AssertExpectations(t)
		},
	)

	t.Run(
		"with 'public-key-path', 'in', 'out' flags specified, but reading the INI file at 'in' fails, "+
			"it returns error",
		func(t *testing.T) {
			realOsExecutor := &os.RealOsExecutor{}

			tmpDir := testutils.TestCwd(t, "vaulted")
			defer stdOs.RemoveAll(tmpDir)

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			pubkeyPathArg := testutils.GenerateAndWritePublicKey(t, tmpDir, "pub.key", privKey)

			outputBuff := &bytes.Buffer{}

			rsaSvc := rsa.NewRsaService(realOsExecutor)

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)
			encContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)
			hclSvc := hcl.NewHclService()

			osExecutor := ostest.NewFakeOsExecutor(t)
			tfSvc := terraform.NewTerraformService()

			inPathArg := "/tmp/example.ini"

			iniSvc := &mockIniService{}
			fakeError := errors.New("readiniatpathError")
			iniSvc.On("ReadIniAtPath", inPathArg).Return(nil, fakeError)

			tfEncMigrationSvc := terraform_encryption_migration.NewTerraformEncryptionMigrationService(
				tfSvc,
			)
			cmdInstance := NewIniCommand(
				osExecutor,
				rsaSvc,
				iniSvc,
				encPassphraseSvc,
				encContentSvc,
				hclSvc,
				tfSvc,
				tfEncMigrationSvc,
			)

			cmdArgs := []string{
				fmt.Sprintf("--public-key-path=%s", pubkeyPathArg),
				fmt.Sprintf("--in=%s", inPathArg),
				"--out=/tmp/example.out",
			}

			_, err = testutils.RunCommandInSameProcess(
				cmdInstance,
				cmdArgs,
				outputBuff,
			)

			assert.Contains(t, err.Error(), "failed to read specified INI file")

			osExecutor.AssertExpectations(t)
		},
	)

	t.Run(
		"with 'public-key-path', 'in', 'out' flags specified, "+
			"but converting parsed INI content to terraform content fails, "+
			"it returns error",
		func(t *testing.T) {
			realOsExecutor := &os.RealOsExecutor{}

			tmpDir := testutils.TestCwd(t, "vaulted")
			defer stdOs.RemoveAll(tmpDir)

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			pubkeyPathArg := testutils.GenerateAndWritePublicKey(t, tmpDir, "pub.key", privKey)

			inPathArg := filepath.Join(tmpDir, "file.ini")
			iniFileContent := `[section1]
key_a = value_b

[section2]
key_b = value_b
key_c = value_c`

			err = realOsExecutor.WriteFile(inPathArg, []byte(iniFileContent), 0644)
			require.Nil(t, err)

			outputBuff := &bytes.Buffer{}

			rsaSvc := rsa.NewRsaService(realOsExecutor)

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)
			encContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)
			hclSvc := hcl.NewHclService()

			osExecutor := ostest.NewFakeOsExecutor(t)

			iniSvc := ini.NewIniService()
			fakeError := errors.New("convertinicontenttoterraformcontentError")
			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := &testTfEncMigration.MockTerraformEncryptionMigrationService{}
			tfEncMigrationSvc.On(
				"ConvertIniContentToLegacyTerraformContent",
				16,
				mock.AnythingOfType("*ini.Content"),
				mock.AnythingOfType("*rsa.PublicKey"),
				mock.Anything,
				mock.Anything,
			).Return(nil, fakeError)

			cmdInstance := NewIniCommand(
				osExecutor,
				rsaSvc,
				iniSvc,
				encPassphraseSvc,
				encContentSvc,
				hclSvc,
				tfSvc,
				tfEncMigrationSvc,
			)

			cmdArgs := []string{
				fmt.Sprintf("--public-key-path=%s", pubkeyPathArg),
				fmt.Sprintf("--in=%s", inPathArg),
				"--out=/tmp/example.out",
			}

			_, err = testutils.RunCommandInSameProcess(
				cmdInstance,
				cmdArgs,
				outputBuff,
			)

			assert.Contains(t, err.Error(), "failed to convert INI content to terraform content")

			osExecutor.AssertExpectations(t)
		},
	)

	t.Run(
		"with 'public-key-path', 'in', 'out' flags specified, "+
			"but converting terraform content to HCL fails, "+
			"it returns error",
		func(t *testing.T) {
			realOsExecutor := &os.RealOsExecutor{}

			tmpDir := testutils.TestCwd(t, "vaulted")
			defer stdOs.RemoveAll(tmpDir)

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			pubkeyPathArg := testutils.GenerateAndWritePublicKey(t, tmpDir, "pub.key", privKey)

			inPathArg := filepath.Join(tmpDir, "file.ini")
			iniFileContent := `[section1]
key_a = value_b

[section2]
key_b = value_b
key_c = value_c`

			err = realOsExecutor.WriteFile(inPathArg, []byte(iniFileContent), 0644)
			require.Nil(t, err)

			outputBuff := &bytes.Buffer{}

			rsaSvc := rsa.NewRsaService(realOsExecutor)

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)
			encContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)
			hclSvc := hcl.NewHclService()

			osExecutor := ostest.NewFakeOsExecutor(t)

			iniSvc := ini.NewIniService()
			realTfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := terraform_encryption_migration.NewTerraformEncryptionMigrationService(
				realTfSvc,
			)

			fakeError := errors.New("TerraformContentToHCLfileError")
			mockTfSvc := &test.MockTerraformSvc{}
			mockTfSvc.Test(t)
			mockTfSvc.On(
				"TerraformContentToHCLfile",
				hclSvc,
				mock.AnythingOfType("*terraform.Content"),
			).Return(nil, fakeError)

			cmdInstance := NewIniCommand(
				osExecutor,
				rsaSvc,
				iniSvc,
				encPassphraseSvc,
				encContentSvc,
				hclSvc,
				mockTfSvc,
				tfEncMigrationSvc,
			)

			cmdArgs := []string{
				fmt.Sprintf("--public-key-path=%s", pubkeyPathArg),
				fmt.Sprintf("--in=%s", inPathArg),
				"--out=/tmp/example.out",
			}

			_, err = testutils.RunCommandInSameProcess(
				cmdInstance,
				cmdArgs,
				outputBuff,
			)

			assert.Contains(
				t,
				err.Error(),
				"failed to transform terraform content to HCL",
			)

			mockTfSvc.AssertExpectations(t)
			osExecutor.AssertExpectations(t)
		},
	)

	t.Run(
		"with 'public-key-path', 'in', 'out' flags specified, "+
			"but creating file at 'out' path fails, "+
			"it returns error",
		func(t *testing.T) {
			realOsExecutor := &os.RealOsExecutor{}

			tmpDir := testutils.TestCwd(t, "vaulted")
			defer stdOs.RemoveAll(tmpDir)

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			pubkeyPathArg := testutils.GenerateAndWritePublicKey(t, tmpDir, "pub.key", privKey)

			inPathArg := filepath.Join(tmpDir, "file.ini")
			iniFileContent := `[section1]
key_a = value_b

[section2]
key_b = value_b
key_c = value_c`

			err = realOsExecutor.WriteFile(inPathArg, []byte(iniFileContent), 0644)
			require.Nil(t, err)

			outputBuff := &bytes.Buffer{}

			rsaSvc := rsa.NewRsaService(realOsExecutor)

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)
			encContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)
			hclSvc := hcl.NewHclService()

			osExecutor := ostest.NewFakeOsExecutor(t)

			iniSvc := ini.NewIniService()
			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := terraform_encryption_migration.NewTerraformEncryptionMigrationService(
				tfSvc,
			)

			cmdInstance := NewIniCommand(
				realOsExecutor,
				rsaSvc,
				iniSvc,
				encPassphraseSvc,
				encContentSvc,
				hclSvc,
				tfSvc,
				tfEncMigrationSvc,
			)

			cmdArgs := []string{
				fmt.Sprintf("--public-key-path=%s", pubkeyPathArg),
				fmt.Sprintf("--in=%s", inPathArg),
				// NOTE: Non-existent and invalid path
				"--out=/1<2<3<4",
			}

			_, err = testutils.RunCommandInSameProcess(
				cmdInstance,
				cmdArgs,
				outputBuff,
			)

			assert.Contains(t, err.Error(), "failed to create file at 'out' path")

			osExecutor.AssertExpectations(t)
		},
	)

	t.Run(
		"with 'public-key-path', 'in', 'out' flags specified, "+
			"and specified 'in' file is parsed successfully as INI file, "+
			"it writes HCL terraform to specified 'out' path",
		func(t *testing.T) {
			realOsExecutor := &os.RealOsExecutor{}

			tmpDir := testutils.TestCwd(t, "vaulted")
			defer stdOs.RemoveAll(tmpDir)

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			pubkeyPathArg := testutils.GenerateAndWritePublicKey(t, tmpDir, "pub.key", privKey)

			inPathArg := filepath.Join(tmpDir, "file.ini")
			iniFileContent := `[section1]
key_a = value_b

[section2]
key_b = value_b
key_c = value_c`

			err = realOsExecutor.WriteFile(inPathArg, []byte(iniFileContent), 0644)
			require.Nil(t, err)

			outputBuff := &bytes.Buffer{}

			rsaSvc := rsa.NewRsaService(realOsExecutor)

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)
			encContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)
			hclSvc := hcl.NewHclService()

			iniSvc := ini.NewIniService()
			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := terraform_encryption_migration.NewTerraformEncryptionMigrationService(
				tfSvc,
			)

			cmdInstance := NewIniCommand(
				realOsExecutor,
				rsaSvc,
				iniSvc,
				encPassphraseSvc,
				encContentSvc,
				hclSvc,
				tfSvc,
				tfEncMigrationSvc,
			)

			outPathArg := filepath.Join(tmpDir, "out.tf")
			cmdArgs := []string{
				fmt.Sprintf("--public-key-path=%s", pubkeyPathArg),
				fmt.Sprintf("--in=%s", inPathArg),
				fmt.Sprintf("--out=%s", outPathArg),
			}

			_, err = testutils.RunCommandInSameProcess(
				cmdInstance,
				cmdArgs,
				outputBuff,
			)
			assert.Nil(t, err)
			assert.Equal(t, "", outputBuff.String())

			outputWrittenFile, err := realOsExecutor.ReadFile(outPathArg)
			require.Nil(t, err)

			regexMatches := vaultedTestUtils.OldTerraformRegex.FindAllStringSubmatch(
				string(outputWrittenFile),
				-1,
			)

			resourceA := regexMatches[0]
			assert.Equal(t, "vault_encrypted_secret_section1_key_a", resourceA[1])
			// NOTE: Encrypted passphrase is not empty
			assert.NotEqual(t, "", resourceA[2])
			// NOTE: Encrypted content is not empty
			assert.NotEqual(t, "", resourceA[3])

			resourceB := regexMatches[1]
			assert.Equal(t, "vault_encrypted_secret_section2_key_b", resourceB[1])
			// NOTE: Encrypted passphrase is not empty
			assert.NotEqual(t, "", resourceB[2])
			// NOTE: Encrypted content is not empty
			assert.NotEqual(t, "", resourceB[3])

			resourceC := regexMatches[2]
			assert.Equal(t, "vault_encrypted_secret_section2_key_c", resourceC[1])
			// NOTE: Encrypted passphrase is not empty
			assert.NotEqual(t, "", resourceC[2])
			// NOTE: Encrypted content is not empty
			assert.NotEqual(t, "", resourceC[3])

			assert.Equal(t, 3, len(regexMatches))
		},
	)
}
