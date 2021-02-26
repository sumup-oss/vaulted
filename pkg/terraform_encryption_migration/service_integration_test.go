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

package terraform_encryption_migration

import (
	"crypto/rand"
	stdRsa "crypto/rsa"
	"errors"
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/sumup-oss/go-pkgs/os/ostest"
	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/ini"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/rsa"
	"github.com/sumup-oss/vaulted/pkg/terraform"
	"github.com/sumup-oss/vaulted/pkg/testutils"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
	testPassphrase "github.com/sumup-oss/vaulted/pkg/vaulted/passphrase/test"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
	testPayload "github.com/sumup-oss/vaulted/pkg/vaulted/payload/test"
)

func TestService_ConvertIniContentToV1ResourceHCL(t *testing.T) {
	t.Run(
		"when `iniContent` has no sections, it returns empty HCL",
		func(t *testing.T) {
			t.Parallel()

			privKey, actualErr := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, actualErr)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			iniContent := ini.NewIniContent()

			encryptedPassphraseSvc := &testPassphrase.MockEncryptedPassphraseService{}
			encryptedPayloadSvc := &testPayload.MockEncryptedPayloadService{}

			actualReturn, actualErr := tfEncMigrationSvc.ConvertIniContentToV1ResourceHCL(
				32,
				iniContent,
				&privKey.PublicKey,
				encryptedPassphraseSvc,
				encryptedPayloadSvc,
			)

			require.Nil(t, actualErr)

			assert.Equal(t, "", string(actualReturn.Bytes()))
		},
	)

	t.Run(
		"when `iniContent` has 1 section, but no values in the section, "+
			"it returns empty HCL",
		func(t *testing.T) {
			t.Parallel()

			privKey, actualErr := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, actualErr)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			iniSection := ini.NewIniSection("section_a")
			iniSection.Values = []*ini.SectionValue{}

			iniContent := ini.NewIniContent()
			iniContent.AddSection(iniSection)

			assert.Equal(t, 1, len(iniContent.SectionsByName))

			encryptedPassphraseSvc := &testPassphrase.MockEncryptedPassphraseService{}
			encryptedPayloadSvc := &testPayload.MockEncryptedPayloadService{}

			actualReturn, actualErr := tfEncMigrationSvc.ConvertIniContentToV1ResourceHCL(
				32,
				iniContent,
				&privKey.PublicKey,
				encryptedPassphraseSvc,
				encryptedPayloadSvc,
			)

			require.Nil(t, actualErr)

			assert.Equal(t, "", string(actualReturn.Bytes()))
		},
	)

	t.Run(
		"when `iniContent` has at least 1 section, but json marshalling of section value fails, "+
			"it returns an error",
		func(t *testing.T) {
			t.Parallel()

			privKey, actualErr := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, actualErr)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			iniSection := ini.NewIniSection("section_a")
			// NOTE: Section value is not JSON serializable.
			// It's expected to be the cause of the JSON marshal error.
			sectionValue := ini.NewIniSectionValue("key_a", make(chan interface{}))

			iniSection.Values = []*ini.SectionValue{sectionValue}

			iniContent := ini.NewIniContent()
			iniContent.AddSection(iniSection)

			assert.Equal(t, 1, len(iniContent.SectionsByName))

			encryptedPassphraseSvc := &testPassphrase.MockEncryptedPassphraseService{}
			encryptedPayloadSvc := &testPayload.MockEncryptedPayloadService{}

			actualReturn, actualErr := tfEncMigrationSvc.ConvertIniContentToV1ResourceHCL(
				32,
				iniContent,
				&privKey.PublicKey,
				encryptedPassphraseSvc,
				encryptedPayloadSvc,
			)

			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				fmt.Sprintf(
					"failed to marshal in JSON value for section: %s, key: %s",
					iniSection.Name,
					sectionValue.KeyName,
				),
			)
		},
	)

	t.Run(
		"when `iniContent` has at least 1 section, but generating of random passphrase fails, "+
			"it returns an error",
		func(t *testing.T) {
			t.Parallel()

			privKey, actualErr := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, actualErr)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			iniSection := ini.NewIniSection("section_a")
			sectionValue := ini.NewIniSectionValue("key_a", "value_a")

			iniSection.Values = []*ini.SectionValue{sectionValue}

			iniContent := ini.NewIniContent()
			iniContent.AddSection(iniSection)

			assert.Equal(t, 1, len(iniContent.SectionsByName))

			fakeError := errors.New("fakeGeneratePassphraseError")
			encryptedPassphraseSvc := &testPassphrase.MockEncryptedPassphraseService{}
			encryptedPassphraseSvc.On(
				"GeneratePassphrase",
				32,
			).Return(nil, fakeError)

			encryptedPayloadSvc := &testPayload.MockEncryptedPayloadService{}

			actualReturn, actualErr := tfEncMigrationSvc.ConvertIniContentToV1ResourceHCL(
				32,
				iniContent,
				&privKey.PublicKey,
				encryptedPassphraseSvc,
				encryptedPayloadSvc,
			)

			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to generate random passphrase",
			)
		},
	)

	t.Run(
		"when `iniContent` has at least 1 section, but encrypting the section value's content fails, "+
			"it returns an error",
		func(t *testing.T) {
			t.Parallel()

			privKey, actualErr := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, actualErr)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			iniSection := ini.NewIniSection("section_a")
			sectionValue := ini.NewIniSectionValue("key_a", "value_a")

			iniSection.Values = []*ini.SectionValue{sectionValue}

			iniContent := ini.NewIniContent()
			iniContent.AddSection(iniSection)

			assert.Equal(t, 1, len(iniContent.SectionsByName))

			b64Svc := base64.NewBase64Service()
			osExecutor := ostest.NewFakeOsExecutor(t)

			rsaSvc := rsa.NewRsaService(osExecutor)

			encryptedPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsaSvc,
			)

			fakeError := errors.New("fakeEncryptError")
			encryptedPayloadSvc := &testPayload.MockEncryptedPayloadService{}
			encryptedPayloadSvc.On(
				"Encrypt",
				mock.AnythingOfType("*rsa.PublicKey"),
				mock.AnythingOfType("*payload.Payload"),
			).Return(nil, fakeError)

			actualReturn, actualErr := tfEncMigrationSvc.ConvertIniContentToV1ResourceHCL(
				32,
				iniContent,
				&privKey.PublicKey,
				encryptedPassphraseSvc,
				encryptedPayloadSvc,
			)

			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				fmt.Sprintf(
					"failed to encrypt content from section: %s, key: %s",
					iniSection.Name,
					sectionValue.KeyName,
				),
			)
		},
	)

	t.Run(
		"when `iniContent` has at least 1 section and generating random passphrase, encryption of "+
			"passphrase and content succeeds, "+
			"it returns HCL with at least 1 terraform resource added",
		func(t *testing.T) {
			t.Parallel()

			privKey, actualErr := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, actualErr)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			iniSection := ini.NewIniSection("section_a")
			sectionValue := ini.NewIniSectionValue("key_a", "value_a")

			iniSection.Values = []*ini.SectionValue{sectionValue}

			iniContent := ini.NewIniContent()
			iniContent.AddSection(iniSection)

			assert.Equal(t, 1, len(iniContent.SectionsByName))

			b64Svc := base64.NewBase64Service()
			osExecutor := ostest.NewFakeOsExecutor(t)

			rsaSvc := rsa.NewRsaService(osExecutor)

			encryptedPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsaSvc,
			)

			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())
			encryptedContentSvc := content.NewV1EncryptedContentService(b64Svc, aesSvc)
			encryptedPayloadSvc := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvc,
				encryptedContentSvc,
			)

			actualReturn, actualErr := tfEncMigrationSvc.ConvertIniContentToV1ResourceHCL(
				32,
				iniContent,
				&privKey.PublicKey,
				encryptedPassphraseSvc,
				encryptedPayloadSvc,
			)

			require.Nil(t, actualErr)
			require.NotNil(t, actualReturn)

			actualReturnString := string(actualReturn.Bytes())

			resourceKey := fmt.Sprintf(
				"vaulted_vault_secret_%s_%s",
				iniSection.Name,
				sectionValue.KeyName,
			)
			path := fmt.Sprintf(
				"secret/%s/%s",
				iniSection.Name,
				sectionValue.KeyName,
			)

			expectedRegex := fmt.Sprintf(`resource "vaulted_vault_secret" "%s" {
  path         = "%s"
  payload_json = "\$VED;1.0::(.+)::(.+)"
}\n`, resourceKey, path)
			assert.Regexp(t, regexp.MustCompile(expectedRegex), actualReturnString)
		},
	)
}

func TestService_MigrateEncryptedTerraformResourceHcl(t *testing.T) {
	t.Run(
		"when failing to parse 'hclBytes', it returns an error",
		func(t *testing.T) {
			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)
			hclParserArg := hcl.NewHclService()
			hclBytesArg := []byte("{ invalid }")

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			legacyEncryptedContentSvcArg := content.NewLegacyEncryptedContentService(
				b64Svc,
				aesSvc,
			)

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			actualReturn, actualErr := tfEncMigrationSvc.MigrateEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				legacyEncryptedContentSvcArg,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(t, actualErr.Error(), "failed to parse HCL")
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes', "+
			"but HCL terraform does not have any `vault_encrypted_secret` resources, "+
			"it returns AST without any modification",
		func(t *testing.T) {
			// NOTE: Memory references are *intentionally* asserted for equality.
			// It's very well known which objects are supposed to be changed.

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			hclBytesArg := []byte(`
	resource "vault_generic_secret" "mysecret" {
		path = "secret/example"
		data_json = "{ 'foo': 'bar' }"
	}
	`)
			hclParserArg := hcl.NewHclService()

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			legacyEncryptedContentSvcArg := content.NewLegacyEncryptedContentService(
				b64Svc,
				aesSvc,
			)

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			expectedReturn, err := hclParserArg.Parse(hclBytesArg)
			require.Nil(t, err)

			actualReturn, actualErr := tfEncMigrationSvc.MigrateEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				legacyEncryptedContentSvcArg,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualErr)

			assert.Equal(t, expectedReturn.Bytes(), actualReturn.Bytes())
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vault_encrypted_secret`, "+
			"but `vault_encrypted_secret` is not a HCL object, "+
			"it returns error",
		func(t *testing.T) {
			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			hclBytesArg := []byte(`resource "vault_encrypted_secret" "mysecret" = "123"`)
			hclParserArg := hcl.NewHclService()

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			legacyEncryptedContentSvcArg := content.NewLegacyEncryptedContentService(
				b64Svc,
				aesSvc,
			)

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			actualReturn, actualErr := tfEncMigrationSvc.MigrateEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				legacyEncryptedContentSvcArg,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to parse HCL",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vault_encrypted_secret`, "+
			"but `vault_encrypted_secret` has less than 3 content keys, "+
			"it returns error",
		func(t *testing.T) {
			// NOTE: Memory references are *intentionally* asserted for equality.
			// It's very well known which objects are supposed to be changed.

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			hclBytesArg := []byte(`
	resource "vault_encrypted_secret" "mysecret" {
		path = "secret/example"
		encrypted_passphrase = ""
	}`)
			hclParserArg := hcl.NewHclService()

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			legacyEncryptedContentSvcArg := content.NewLegacyEncryptedContentService(
				b64Svc,
				aesSvc,
			)

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			actualReturn, actualErr := tfEncMigrationSvc.MigrateEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				legacyEncryptedContentSvcArg,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to read `encrypted_data_json` attr value for `vault_encrypted_secret.mysecret`",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vault_encrypted_secret`, "+
			"but `vault_encrypted_secret` has non-string key, "+
			"it returns error",
		func(t *testing.T) {
			// NOTE: Memory references are *intentionally* asserted for equality.
			// It's very well known which objects are supposed to be changed.

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			hclBytesArg := []byte(`
	resource "vault_encrypted_secret" "mysecret" {
		1 = "1234"
		encrypted_passphrase = "a1b2c3d4"
		encrypted_data_json = "a1b2c3d4"
	}`)
			hclParserArg := hcl.NewHclService()

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			legacyEncryptedContentSvcArg := content.NewLegacyEncryptedContentService(
				b64Svc,
				aesSvc,
			)

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			actualReturn, actualErr := tfEncMigrationSvc.MigrateEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				legacyEncryptedContentSvcArg,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to parse HCL",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vault_encrypted_secret`, "+
			"but `vault_encrypted_secret` has non-string 'encrypted_passphrase' value, "+
			"it returns error",
		func(t *testing.T) {
			// NOTE: Memory references are *intentionally* asserted for equality.
			// It's very well known which objects are supposed to be changed.

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			hclBytesArg := []byte(`
	resource "vault_encrypted_secret" "mysecret" {
		path = "secret/example"
		encrypted_passphrase = 1234
		encrypted_data_json = "a1b2c3d4"
	}`)
			hclParserArg := hcl.NewHclService()

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			legacyEncryptedContentSvcArg := content.NewLegacyEncryptedContentService(
				b64Svc,
				aesSvc,
			)

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			actualReturn, actualErr := tfEncMigrationSvc.MigrateEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				legacyEncryptedContentSvcArg,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to read `encrypted_passphrase` attr value for "+
					"`vault_encrypted_secret.mysecret`",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vault_encrypted_secret`, "+
			"but `vault_encrypted_secret` has non-string 'encrypted_data_json' value, "+
			"it returns error",
		func(t *testing.T) {
			// NOTE: Memory references are *intentionally* asserted for equality.
			// It's very well known which objects are supposed to be changed.

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			hclBytesArg := []byte(`
	resource "vault_encrypted_secret" "mysecret" {
		path = "secret/example"
		encrypted_passphrase = "a1b2c3d4"
		encrypted_data_json = 1234
	}`)
			hclParserArg := hcl.NewHclService()

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			legacyEncryptedContentSvcArg := content.NewLegacyEncryptedContentService(
				b64Svc,
				aesSvc,
			)

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			actualReturn, actualErr := tfEncMigrationSvc.MigrateEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				legacyEncryptedContentSvcArg,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to read `encrypted_data_json` attr value for "+
					"`vault_encrypted_secret.mysecret`",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vault_encrypted_secret`, "+
			"but `vault_encrypted_secret` has empty 'encrypted_data_json' string value, "+
			"it returns error",
		func(t *testing.T) {
			// NOTE: Memory references are *intentionally* asserted for equality.
			// It's very well known which objects are supposed to be changed.

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			hclBytesArg := []byte(`
	resource "vault_encrypted_secret" "mysecret" {
		path = "secret/example"
		encrypted_passphrase = "a1b2c3d4"
		encrypted_data_json = ""
	}`)
			hclParserArg := hcl.NewHclService()

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			legacyEncryptedContentSvcArg := content.NewLegacyEncryptedContentService(
				b64Svc,
				aesSvc,
			)

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			actualReturn, actualErr := tfEncMigrationSvc.MigrateEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				legacyEncryptedContentSvcArg,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"empty `encrypted_data_json` attr value for "+
					"`vault_encrypted_secret.mysecret`",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vault_encrypted_secret`, "+
			"but `vault_encrypted_secret` has empty 'encrypted_passphrase' string value, "+
			"it returns error",
		func(t *testing.T) {
			// NOTE: Memory references are *intentionally* asserted for equality.
			// It's very well known which objects are supposed to be changed.

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			hclBytesArg := []byte(`
	resource "vault_encrypted_secret" "mysecret" {
		path = "secret/example"
		encrypted_passphrase = ""
		encrypted_data_json = "a1b2c3d4"
	}`)
			hclParserArg := hcl.NewHclService()

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			legacyEncryptedContentSvcArg := content.NewLegacyEncryptedContentService(
				b64Svc,
				aesSvc,
			)

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			actualReturn, actualErr := tfEncMigrationSvc.MigrateEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				legacyEncryptedContentSvcArg,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"empty `encrypted_passphrase` attr value for "+
					"`vault_encrypted_secret.mysecret`",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vault_encrypted_secret`, "+
			"but `vault_encrypted_secret` has non-base64 deserializable "+
			"'encrypted_passphrase' string value, "+
			"it returns error",
		func(t *testing.T) {
			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			hclBytesArg := []byte(`
	resource "vault_encrypted_secret" "mysecret" {
		path = "secret/example"
		encrypted_passphrase = "WvLTlMrX9NpYDQ\n\n\nlEIFlnDB=="
		encrypted_data_json = "a1b2c3d4"
	}`)
			hclParserArg := hcl.NewHclService()

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			legacyEncryptedContentSvcArg := content.NewLegacyEncryptedContentService(
				b64Svc,
				aesSvc,
			)

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)

			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			actualReturn, actualErr := tfEncMigrationSvc.MigrateEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				legacyEncryptedContentSvcArg,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to deserialize `encrypted_passphrase` attr value for "+
					"`vault_encrypted_secret.mysecret`",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vault_encrypted_secret`, "+
			"but `vault_encrypted_secret` has non-decryptable "+
			"'encrypted_passphrase' string value, "+
			"it returns error",
		func(t *testing.T) {
			// NOTE: Memory references are *intentionally* asserted for equality.
			// It's very well known which objects are supposed to be changed.

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			hclBytesArg := []byte(`
	resource "vault_encrypted_secret" "mysecret" {
		path = "secret/example"
		encrypted_passphrase = "dGVzdAo="
		encrypted_data_json = "dGVzdAo="
	}`)
			hclParserArg := hcl.NewHclService()

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			legacyEncryptedContentSvcArg := content.NewLegacyEncryptedContentService(
				b64Svc,
				aesSvc,
			)

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)

			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			actualReturn, actualErr := tfEncMigrationSvc.MigrateEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				legacyEncryptedContentSvcArg,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to decrypt `encrypted_passphrase` attr value for "+
					"`vault_encrypted_secret.mysecret`",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vault_encrypted_secret`, "+
			"but `vault_encrypted_secret` has non-deserializable "+
			"'encrypted_data_json' string value, "+
			"it returns error",
		func(t *testing.T) {
			// NOTE: Memory references are *intentionally* asserted for equality.
			// It's very well known which objects are supposed to be changed.

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			osExecutor := ostest.NewFakeOsExecutor(t)
			b64Svc := base64.NewBase64Service()
			rsaSvc := rsa.NewRsaService(osExecutor)
			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

			passphrase, err := encryptedPassphraseSvcArg.GeneratePassphrase(16)
			require.Nil(t, err)

			encPassphrase, err := encryptedPassphraseSvcArg.Encrypt(&privKey.PublicKey, passphrase)
			require.Nil(t, err)

			serializedEncPassphrase, err := encryptedPassphraseSvcArg.Serialize(encPassphrase)
			require.Nil(t, err)

			hclBytesArg := []byte(
				fmt.Sprintf(
					`resource "vault_encrypted_secret" "mysecret" {
		path = "secret/example"
		encrypted_passphrase = "%s"
		encrypted_data_json = "dGV\nz\ndAo="
	}`,
					serializedEncPassphrase,
				),
			)
			hclParserArg := hcl.NewHclService()

			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			legacyEncryptedContentSvcArg := content.NewLegacyEncryptedContentService(
				b64Svc,
				aesSvc,
			)

			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			actualReturn, actualErr := tfEncMigrationSvc.MigrateEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				legacyEncryptedContentSvcArg,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to deserialize `encrypted_data_json` attr value for "+
					"`vault_encrypted_secret.mysecret`",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vault_encrypted_secret`, "+
			"but `vault_encrypted_secret` has non-decryptable "+
			"'encrypted_data_json' string value, "+
			"it returns error",
		func(t *testing.T) {
			// NOTE: Memory references are *intentionally* asserted for equality.
			// It's very well known which objects are supposed to be changed.

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			osExecutor := ostest.NewFakeOsExecutor(t)
			b64Svc := base64.NewBase64Service()
			rsaSvc := rsa.NewRsaService(osExecutor)
			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

			passphrase, err := encryptedPassphraseSvcArg.GeneratePassphrase(16)
			require.Nil(t, err)

			encPassphrase, err := encryptedPassphraseSvcArg.Encrypt(&privKey.PublicKey, passphrase)
			require.Nil(t, err)

			serializedEncPassphrase, err := encryptedPassphraseSvcArg.Serialize(encPassphrase)
			require.Nil(t, err)

			hclBytesArg := []byte(
				fmt.Sprintf(
					`resource "vault_encrypted_secret" "mysecret" {
		path = "secret/example"
		encrypted_passphrase = "%s"
		encrypted_data_json = "dGVzdAo="
	}`,
					serializedEncPassphrase,
				),
			)
			hclParserArg := hcl.NewHclService()

			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			legacyEncryptedContentSvcArg := content.NewLegacyEncryptedContentService(
				b64Svc,
				aesSvc,
			)

			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			actualReturn, actualErr := tfEncMigrationSvc.MigrateEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				legacyEncryptedContentSvcArg,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to decrypt `encrypted_data_json` attr value for "+
					"`vault_encrypted_secret.mysecret`",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vault_encrypted_secret`, "+
			"but fails to generate passphrase for new `vault_encrypted_secret` resource"+
			"it returns error",
		func(t *testing.T) {
			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			b64Svc := base64.NewBase64Service()

			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())
			osExecutor := ostest.NewFakeOsExecutor(t)
			rsaSvc := rsa.NewRsaService(osExecutor)
			realEncryptedPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsaSvc,
			)
			passphrase, err := realEncryptedPassphraseSvc.GeneratePassphrase(16)
			require.Nil(t, err)

			encPassphrase, err := realEncryptedPassphraseSvc.Encrypt(&privKey.PublicKey, passphrase)
			require.Nil(t, err)

			serializedEncPassphrase, err := realEncryptedPassphraseSvc.Serialize(encPassphrase)
			require.Nil(t, err)

			legacyEncContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)

			encContent, err := legacyEncContentSvc.Encrypt(
				passphrase,
				content.NewContent(
					[]byte("content_a"),
				),
			)
			require.Nil(t, err)

			serializedEncContent, err := legacyEncContentSvc.Serialize(encContent)
			require.Nil(t, err)

			hclBytesArg := []byte(
				fmt.Sprintf(
					`resource "vault_encrypted_secret" "mysecret" {
		path = "secret/example"
		encrypted_passphrase = "%s"
		encrypted_data_json = "%s"
	}`,
					serializedEncPassphrase,
					serializedEncContent,
				),
			)
			hclParserArg := hcl.NewHclService()

			legacyEncryptedContentSvcArg := content.NewLegacyEncryptedContentService(
				b64Svc,
				aesSvc,
			)

			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				realEncryptedPassphraseSvc,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			fakeError := errors.New("fakeGeneratePassphraseError")
			encryptedPassphraseSvcArg := &testPassphrase.MockEncryptedPassphraseService{}

			encryptedPassphraseSvcArg.On(
				"Deserialize",
				mock.AnythingOfType("[]uint8"),
			).Return(encPassphrase, nil)

			encryptedPassphraseSvcArg.On(
				"Decrypt",
				privKey,
				encPassphrase,
			).Return(passphrase, nil)

			encryptedPassphraseSvcArg.On(
				"GeneratePassphrase",
				32,
			).Return(
				nil,
				fakeError,
			)

			actualReturn, actualErr := tfEncMigrationSvc.MigrateEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				legacyEncryptedContentSvcArg,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to generate new encrypted passphrase for "+
					"`vault_encrypted_secret.mysecret`",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vault_encrypted_secret`, "+
			"but fails to encrypt payload for new terraform resource, "+
			"it returns error",
		func(t *testing.T) {
			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			b64Svc := base64.NewBase64Service()

			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())
			osExecutor := ostest.NewFakeOsExecutor(t)
			rsaSvc := rsa.NewRsaService(osExecutor)
			realEncryptedPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsaSvc,
			)
			passphraseArg, err := realEncryptedPassphraseSvc.GeneratePassphrase(16)
			require.Nil(t, err)

			encPassphrase, err := realEncryptedPassphraseSvc.Encrypt(&privKey.PublicKey, passphraseArg)
			require.Nil(t, err)

			serializedEncPassphrase, err := realEncryptedPassphraseSvc.Serialize(encPassphrase)
			require.Nil(t, err)

			legacyEncContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)

			encContent, err := legacyEncContentSvc.Encrypt(
				passphraseArg,
				content.NewContent(
					[]byte("content_a"),
				),
			)
			require.Nil(t, err)

			serializedEncContent, err := legacyEncContentSvc.Serialize(encContent)
			require.Nil(t, err)

			hclBytesArg := []byte(
				fmt.Sprintf(
					`resource "vault_encrypted_secret" "mysecret" {
		path = "secret/example"
		encrypted_passphrase = "%s"
		encrypted_data_json = "%s"
	}`,
					serializedEncPassphrase,
					serializedEncContent,
				),
			)
			hclParserArg := hcl.NewHclService()

			legacyEncryptedContentSvcArg := content.NewLegacyEncryptedContentService(
				b64Svc,
				aesSvc,
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsaSvc,
			)
			encryptedPayloadSvcArg := &testPayload.MockEncryptedPayloadService{}
			encryptedPayloadSvcArg.Test(t)

			fakeError := errors.New("fakeEncrypt")
			encryptedPayloadSvcArg.On(
				"Encrypt",
				&privKey.PublicKey,
				mock.AnythingOfType("*payload.Payload"),
			).Return(nil, fakeError)

			actualReturn, actualErr := tfEncMigrationSvc.MigrateEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				legacyEncryptedContentSvcArg,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to encrypt new encrypted payload for "+
					"`vault_encrypted_secret.mysecret`",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vault_encrypted_secret`, "+
			"but fails to serialize encrypted payload for new terraform resource, "+
			"it returns error",
		func(t *testing.T) {
			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			b64Svc := base64.NewBase64Service()

			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())
			osExecutor := ostest.NewFakeOsExecutor(t)
			rsaSvc := rsa.NewRsaService(osExecutor)
			realEncryptedPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsaSvc,
			)
			passphraseArg, err := realEncryptedPassphraseSvc.GeneratePassphrase(16)
			require.Nil(t, err)

			encPassphrase, err := realEncryptedPassphraseSvc.Encrypt(&privKey.PublicKey, passphraseArg)
			require.Nil(t, err)

			serializedEncPassphrase, err := realEncryptedPassphraseSvc.Serialize(encPassphrase)
			require.Nil(t, err)

			legacyEncContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)

			encContent, err := legacyEncContentSvc.Encrypt(
				passphraseArg,
				content.NewContent(
					[]byte("content_a"),
				),
			)
			require.Nil(t, err)

			serializedEncContent, err := legacyEncContentSvc.Serialize(encContent)
			require.Nil(t, err)

			hclBytesArg := []byte(
				fmt.Sprintf(
					`resource "vault_encrypted_secret" "mysecret" {
		path = "secret/example"
		encrypted_passphrase = "%s"
		encrypted_data_json = "%s"
	}`,
					serializedEncPassphrase,
					serializedEncContent,
				),
			)
			hclParserArg := hcl.NewHclService()

			legacyEncryptedContentSvcArg := content.NewLegacyEncryptedContentService(
				b64Svc,
				aesSvc,
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigratioNSvc := NewTerraformEncryptionMigrationService(tfSvc)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsaSvc,
			)
			encryptedPayloadSvcArg := &testPayload.MockEncryptedPayloadService{}
			encryptedPayloadSvcArg.Test(t)

			encPassphrase, err = realEncryptedPassphraseSvc.Encrypt(&privKey.PublicKey, passphraseArg)
			require.Nil(t, err)

			encContent, err = legacyEncContentSvc.Encrypt(
				passphraseArg,
				content.NewContent(
					[]byte("content_a"),
				),
			)
			require.Nil(t, err)

			encPayload := payload.NewEncryptedPayload(
				header.NewHeader(),
				encPassphrase,
				encContent,
			)

			encryptedPayloadSvcArg.On(
				"Encrypt",
				&privKey.PublicKey,
				mock.AnythingOfType("*payload.Payload"),
			).Return(encPayload, nil)

			fakeError := errors.New("fakeSerialize")
			encryptedPayloadSvcArg.On(
				"Serialize",
				encPayload,
			).Return(nil, fakeError)

			actualReturn, actualErr := tfEncMigratioNSvc.MigrateEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				legacyEncryptedContentSvcArg,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to serialize new encrypted payload for "+
					"`vault_encrypted_secret.mysecret`",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vault_encrypted_secret`, "+
			" and succeeds to encrypt and serialize payload "+
			"it returns AST with modified resources",
		func(t *testing.T) {
			t.Parallel()

			tfSvc := terraform.NewTerraformService()
			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			osExecutor := ostest.NewFakeOsExecutor(t)
			b64Svc := base64.NewBase64Service()
			rsaSvc := rsa.NewRsaService(osExecutor)
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)
			legacyEncContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)

			// NOTE: 16 key length since we're using AES CBC for legacy encryption strategy
			passphraseA, err := encPassphraseSvc.GeneratePassphrase(16)
			require.Nil(t, err)

			encPassphraseA, err := encPassphraseSvc.Encrypt(&privKey.PublicKey, passphraseA)
			require.Nil(t, err)

			serializedEncPassphraseA, err := encPassphraseSvc.Serialize(encPassphraseA)
			require.Nil(t, err)

			contentA := content.NewContent([]byte("content_a"))
			encContentA, err := legacyEncContentSvc.Encrypt(passphraseA, contentA)
			require.Nil(t, err)

			serializedEncContentA, err := legacyEncContentSvc.Serialize(encContentA)
			require.Nil(t, err)

			// NOTE: 16 key length since we're using AES CBC for legacy encryption strategy
			passphraseB, err := encPassphraseSvc.GeneratePassphrase(16)
			require.Nil(t, err)

			encPassphraseB, err := encPassphraseSvc.Encrypt(&privKey.PublicKey, passphraseB)
			require.Nil(t, err)

			serializedEncPassphraseB, err := encPassphraseSvc.Serialize(encPassphraseB)
			require.Nil(t, err)

			contentB := content.NewContent([]byte("content_b"))
			encContentB, err := legacyEncContentSvc.Encrypt(passphraseB, contentB)
			require.Nil(t, err)

			serializedEncContentB, err := legacyEncContentSvc.Serialize(encContentB)
			require.Nil(t, err)

			hclSvcArg := hcl.NewHclService()
			hclBytesArg := fmt.Sprintf(
				`resource "vault_encrypted_secret" "my_secret_a" {
  path = "secret/my_app/a"
  encrypted_passphrase = "%s"
  encrypted_data_json = "%s"
}
resource "vault_encrypted_secret" "my_secret_b" {
  path = "secret/my_app/b"
  encrypted_passphrase = "%s"
  encrypted_data_json = "%s"
}`,
				serializedEncPassphraseA,
				serializedEncContentA,
				serializedEncPassphraseB,
				serializedEncContentB,
			)

			encContentSvc := content.NewV1EncryptedContentService(b64Svc, aesSvc)

			encPayloadSvc := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encPassphraseSvc,
				encContentSvc,
			)

			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)
			actualReturn, actualErr := tfEncMigrationSvc.MigrateEncryptedTerraformResourceHcl(
				hclSvcArg,
				[]byte(hclBytesArg),
				privKey,
				&privKey.PublicKey,
				legacyEncContentSvc,
				encPassphraseSvc,
				encPayloadSvc,
			)

			osExecutor.AssertExpectations(t)

			require.Nil(t, actualErr)

			expectedRegex := regexp.MustCompile(`resource "vaulted_vault_secret" "my_secret_a" {
  path(?:\s+)= "secret/my_app/a"
  encrypted_payload(?:\s+)= "(.+)"
}
resource "vaulted_vault_secret" "my_secret_b" {
  path(?:\s+)= "secret/my_app/b"
  encrypted_payload(?:\s+)= "(.+)"
}`)

			actualReturnString := string(actualReturn.Bytes())
			regexMatches := expectedRegex.FindAllStringSubmatch(actualReturnString, -1)
			require.Equal(t, 1, len(regexMatches))
			require.Equal(t, 3, len(regexMatches[0]))

			match := testutils.VaultedPayloadRegex.FindAllStringSubmatch(regexMatches[0][1], -1)
			assert.Equal(t, 1, len(match))
			match = testutils.VaultedPayloadRegex.FindAllStringSubmatch(regexMatches[0][2], -1)
			assert.Equal(t, 1, len(match))
		},
	)
}

func TestService_RotateOrRekeyEncryptedTerraformResourceHcl(t *testing.T) {
	t.Run(
		"when failing to parse 'hclBytes', it returns an error",
		func(t *testing.T) {
			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)
			hclParserArg := hcl.NewHclService()
			hclBytesArg := []byte("{ invalid }")

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			actualReturn, actualErr := tfEncMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"Failed to parse HCL, encountered: 1 errs.",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes', "+
			"but HCL terraform does not have any `vaulted_vault_secret` resources, "+
			"it returns AST without any modification",
		func(t *testing.T) {
			// NOTE: Memory references are *intentionally* asserted for equality.
			// It's very well known which objects are supposed to be changed.

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			hclBytesArg := []byte(`
resource "vault_generic_secret" "mysecret" {
	path = "secret/example"
	data_json = "{ 'foo': 'bar' }"
}
`)
			hclParserArg := hcl.NewHclService()

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			expectedReturn, err := hclParserArg.Parse(hclBytesArg)
			require.Nil(t, err)

			actualReturn, actualErr := tfEncMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualErr)

			assert.Equal(t, expectedReturn.Bytes(), actualReturn.Bytes())
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vaulted_vault_secret`, "+
			"but `vaulted_vault_secret` is not a HCL object, "+
			"it returns error",
		func(t *testing.T) {
			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			hclBytesArg := []byte(`resource "vaulted_vault_secret" "mysecret" = "123"`)
			hclParserArg := hcl.NewHclService()

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			actualReturn, actualErr := tfEncMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"Failed to parse HCL, encountered: 1 errs.",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vaulted_vault_secret`, "+
			"but `vaulted_vault_secret` has no `payload_json`, "+
			"it returns error",
		func(t *testing.T) {
			// NOTE: Memory references are *intentionally* asserted for equality.
			// It's very well known which objects are supposed to be changed.

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			hclBytesArg := []byte(`
	resource "vaulted_vault_secret" "mysecret" {
		path = "secret/example"
	}`)
			hclParserArg := hcl.NewHclService()

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			actualReturn, actualErr := tfEncMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to read `payload_json` attr value for `vaulted_vault_secret.mysecret`",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vaulted_vault_secret`, "+
			"but `vaulted_vault_secret` has non-string 'payload_json' value, "+
			"it returns error",
		func(t *testing.T) {
			// NOTE: Memory references are *intentionally* asserted for equality.
			// It's very well known which objects are supposed to be changed.

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			hclBytesArg := []byte(`
	resource "vaulted_vault_secret" "mysecret" {
		path = "secret/example"
		payload_json = 1234
	}`)
			hclParserArg := hcl.NewHclService()

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			actualReturn, actualErr := tfEncMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to read `payload_json` attr value for `vaulted_vault_secret.mysecret`",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vaulted_vault_secret`, "+
			"but `vaulted_vault_secret` has empty 'payload_json' string value, "+
			"it returns error",
		func(t *testing.T) {
			// NOTE: Memory references are *intentionally* asserted for equality.
			// It's very well known which objects are supposed to be changed.

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			hclBytesArg := []byte(`
	resource "vaulted_vault_secret" "mysecret" {
		path = "secret/example"
		payload_json = ""
	}`)
			hclParserArg := hcl.NewHclService()

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			actualReturn, actualErr := tfEncMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"empty `payload_json` attr value for `vaulted_vault_secret.mysecret`",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vaulted_vault_secret`, "+
			"but `vaulted_vault_secret` has non-base64 deserializable "+
			"'payload_json' string value, it returns error",
		func(t *testing.T) {
			// NOTE: Memory references are *intentionally* asserted for equality.
			// It's very well known which objects are supposed to be changed.

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			hclBytesArg := []byte(`
	resource "vaulted_vault_secret" "mysecret" {
		path = "secret/example"
		payload_json = "WvLTlMrX9NpYDQ\n\n\nlEIFlnDB=="
	}`)
			hclParserArg := hcl.NewHclService()

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)

			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			actualReturn, actualErr := tfEncMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to deserialize `payload_json` attr's value for `vaulted_vault_secret.mysecret`",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vaulted_vault_secret`, "+
			"but `vaulted_vault_secret` has non-decryptable "+
			"'payload_json' string value, "+
			"it returns error",
		func(t *testing.T) {
			// NOTE: Memory references are *intentionally* asserted for equality.
			// It's very well known which objects are supposed to be changed.

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			hclBytesArg := []byte(`
	resource "vaulted_vault_secret" "mysecret" {
		path = "secret/example"
		payload_json = "$VED;1.0::bkWby39RtkomRc8TI4zOqI4qLAOVP2nWxPIyZ990yQoOzb2RRGZ3EqNoopm7anJgGLTDY4UxeSDOVfe2IhI8JYr8MwGkCru3Al6GUsaLBuv7hv/C7NbmoYmff9nPOipFKmOXRPdwC4PeTW29jjDXSfCWwSdvWMXsyqfNXKwBc2ZA+aOqD2hESb7WITSeBsjOizpfBbOuNLhTTdRhVCbIHKRjcz6sWxMsyE7/yjjUPtkf+zs6WixoBPh52bukmPWESaAe1bv9IV/PUBGQTMvTzzdsMG7JTBnH/IZRnUYo6SAsg8hnQAQZmARK6oIZ0Lcj38p+hpAbJG2bSFGFDJmJUdQqnygOGUcOp05ZElFwjHkE1JbRQ/KQV8Izrmy47et+OOUlv0K2KnJ+Yk9HBHRVkk+DuvaTLHjF+rIB/CpEfipjGjkoFvmS4HYUxNhx+KYGW7eZqevClPtWjQMMlpWzDJQwnYyDrwPUwhuHv5/G/CLKrNJ9JEnAcGTxss3oJCwj9jUtbwzit+6aC0PfskXYuujxomMnD3BD78NupmEF40Cf0kefdKyfhzHzXhv5qfdUAJ6F4cpwRPOR5U0zIpFPLq1xKM66Ju5mG4omKGe1yHwKJz6/APTA4OXbVjVPDPhnz5EGiYq1fK+Jatpz3AHbjJaC7fo137iUbZDfCF10LDQ=::u5LPpDE9BfeIvskvgR2PFfK6MDRZTb58h2lDO3dtTaU="
	}`)
			hclParserArg := hcl.NewHclService()

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			osExecutor := ostest.NewFakeOsExecutor(t)

			encryptedPassphraseSvcArg := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)

			encryptedPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvcArg,
				content.NewLegacyEncryptedContentService(b64Svc, aesSvc),
			)

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			actualReturn, actualErr := tfEncMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				encryptedPassphraseSvcArg,
				encryptedPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to decrypt `payload_json` attr's value for `vaulted_vault_secret.mysecret`",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vaulted_vault_secret`, "+
			"but fails to generate passphrase for new `vaulted_vault_secret` resource"+
			"it returns error",
		func(t *testing.T) {
			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			b64Svc := base64.NewBase64Service()

			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())
			osExecutor := ostest.NewFakeOsExecutor(t)
			rsaSvc := rsa.NewRsaService(osExecutor)
			realEncryptedPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsaSvc,
			)
			realEncContentSvc := content.NewV1EncryptedContentService(b64Svc, aesSvc)
			encPayloadSvcArg := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				realEncryptedPassphraseSvc,
				realEncContentSvc,
			)

			passphrase, err := realEncryptedPassphraseSvc.GeneratePassphrase(32)
			require.Nil(t, err)

			contentArg := content.NewContent([]byte("mysecret!"))
			payload := payload.NewPayload(
				header.NewHeader(),
				passphrase,
				contentArg,
			)

			encPayload, err := encPayloadSvcArg.Encrypt(&privKey.PublicKey, payload)
			serializedEncPayload, err := encPayloadSvcArg.Serialize(encPayload)
			require.Nil(t, err)

			hclBytesArg := []byte(
				fmt.Sprintf(
					`resource "vaulted_vault_secret" "mysecret" {
		path = "secret/example"
		payload_json = "%s"
	}`,
					serializedEncPayload,
				),
			)
			hclParserArg := hcl.NewHclService()

			tfSvc := terraform.NewTerraformService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			fakeError := errors.New("fakeGeneratePassphraseError")
			encryptedPassphraseSvcArg := &testPassphrase.MockEncryptedPassphraseService{}
			encryptedPassphraseSvcArg.On(
				"GeneratePassphrase",
				32,
			).Return(
				nil,
				fakeError,
			)

			actualReturn, actualErr := tfEncMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				privKey,
				&privKey.PublicKey,
				encryptedPassphraseSvcArg,
				encPayloadSvcArg,
			)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to generate new passphrase for `vaulted_vault_secret.mysecret`",
			)
		},
	)

	t.Run(
		"when succeeding to parse 'hclBytes' which has `vaulted_vault_secret`, "+
			" and succeeds to encrypt and serialize payload "+
			"it returns AST with modified resources",
		func(t *testing.T) {
			t.Parallel()

			tfSvc := terraform.NewTerraformService()
			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

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

			passphrase, err := encPassphraseSvc.GeneratePassphrase(32)
			require.Nil(t, err)

			payload := payload.NewPayload(
				header.NewHeader(),
				passphrase,
				content.NewContent(
					[]byte("mysecret!"),
				),
			)

			encPayload, err := encPayloadSvc.Encrypt(&privKey.PublicKey, payload)
			require.Nil(t, err)

			serializedPayloadJSON, err := encPayloadSvc.Serialize(encPayload)

			hclSvcArg := hcl.NewHclService()
			hclBytesArg := fmt.Sprintf(
				`resource "vaulted_vault_secret" "my_secret_b" {
  path         = "secret/my_app/b"
  payload_json = "%s"
}`,
				serializedPayloadJSON,
			)

			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)
			actualReturn, actualErr := tfEncMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclSvcArg,
				[]byte(hclBytesArg),
				privKey,
				&privKey.PublicKey,
				encPassphraseSvc,
				encPayloadSvc,
			)

			osExecutor.AssertExpectations(t)

			require.Nil(t, actualErr)

			actualReturnString := string(actualReturn.Bytes())
			expectedRegex := regexp.MustCompile(
				`resource "vaulted_vault_secret" "my_secret_b" {
  path         = "secret/my_app/b"
  payload_json = "(.+)"
}`,
			)
			regexMatches := expectedRegex.FindAllStringSubmatch(actualReturnString, -1)
			require.Equal(t, 1, len(regexMatches))
			require.Equal(t, 2, len(regexMatches[0]))

			match := testutils.VaultedPayloadRegex.FindAllStringSubmatch(regexMatches[0][1], -1)
			assert.Equal(t, 1, len(match))
			// NOTE: Make sure the value was changed
			assert.NotEqual(t, match[0], serializedPayloadJSON)
		},
	)
}
