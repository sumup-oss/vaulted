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
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sumup-oss/go-pkgs/os/ostest"
	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/rsa"
	"github.com/sumup-oss/vaulted/pkg/terraform"
	"github.com/sumup-oss/vaulted/pkg/testutils"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

func TestService_RotateOrRekeyEncryptedTerraformResourceHcl(t *testing.T) {
	t.Run(
		"when failing to parse 'hclBytes', it returns an error",
		func(t *testing.T) {
			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			tfSvc := terraform.NewService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)
			hclParserArg := hcl.NewHclService()
			hclBytesArg := []byte("{ invalid }")

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			osExecutor := ostest.NewFakeOsExecutor(t)

			passphraseSvc := passphrase.NewService()
			payloadSerdeSvc := payload.NewSerdeService(b64Svc)

			rsaSvc := rsa.NewRsaService(osExecutor)
			contentSvc := content.NewV1Service(b64Svc, aesSvc)
			passphraseDecrypter := passphrase.NewDecryptionRsaPKCS1v15Service(
				privKey,
				rsaSvc,
			)
			oldPayloadDecryptor := payload.NewDecryptionService(passphraseDecrypter, contentSvc)

			passphraseEncrypter := passphrase.NewEncryptionRsaPKCS1v15Service(rsaSvc, &privKey.PublicKey)
			newPayloadEncryptor := payload.NewEncryptionService(passphraseEncrypter, contentSvc)

			actualReturn, actualErr := tfEncMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				passphraseSvc,
				payloadSerdeSvc,
				oldPayloadDecryptor,
				newPayloadEncryptor,
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

			passphraseSvc := passphrase.NewService()
			payloadSerdeSvc := payload.NewSerdeService(b64Svc)

			rsaSvc := rsa.NewRsaService(osExecutor)
			contentSvc := content.NewV1Service(b64Svc, aesSvc)
			passphraseDecrypter := passphrase.NewDecryptionRsaPKCS1v15Service(
				privKey,
				rsaSvc,
			)
			oldPayloadDecryptor := payload.NewDecryptionService(passphraseDecrypter, contentSvc)

			passphraseEncrypter := passphrase.NewEncryptionRsaPKCS1v15Service(rsaSvc, &privKey.PublicKey)
			newPayloadEncryptor := payload.NewEncryptionService(passphraseEncrypter, contentSvc)

			expectedReturn, err := hclParserArg.Parse(hclBytesArg)
			require.Nil(t, err)

			tfSvc := terraform.NewService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)
			actualReturn, actualErr := tfEncMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				passphraseSvc,
				payloadSerdeSvc,
				oldPayloadDecryptor,
				newPayloadEncryptor,
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

			passphraseSvc := passphrase.NewService()
			payloadSerdeSvc := payload.NewSerdeService(b64Svc)

			rsaSvc := rsa.NewRsaService(osExecutor)
			contentSvc := content.NewV1Service(b64Svc, aesSvc)
			passphraseDecrypter := passphrase.NewDecryptionRsaPKCS1v15Service(
				privKey,
				rsaSvc,
			)
			oldPayloadDecryptor := payload.NewDecryptionService(passphraseDecrypter, contentSvc)

			passphraseEncrypter := passphrase.NewEncryptionRsaPKCS1v15Service(rsaSvc, &privKey.PublicKey)
			newPayloadEncryptor := payload.NewEncryptionService(passphraseEncrypter, contentSvc)

			tfSvc := terraform.NewService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)

			actualReturn, actualErr := tfEncMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				passphraseSvc,
				payloadSerdeSvc,
				oldPayloadDecryptor,
				newPayloadEncryptor,
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

			passphraseSvc := passphrase.NewService()
			payloadSerdeSvc := payload.NewSerdeService(b64Svc)

			rsaSvc := rsa.NewRsaService(osExecutor)
			contentSvc := content.NewV1Service(b64Svc, aesSvc)
			passphraseDecrypter := passphrase.NewDecryptionRsaPKCS1v15Service(
				privKey,
				rsaSvc,
			)
			oldPayloadDecryptor := payload.NewDecryptionService(passphraseDecrypter, contentSvc)

			passphraseEncrypter := passphrase.NewEncryptionRsaPKCS1v15Service(rsaSvc, &privKey.PublicKey)
			newPayloadEncryptor := payload.NewEncryptionService(passphraseEncrypter, contentSvc)

			tfSvc := terraform.NewService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)
			actualReturn, actualErr := tfEncMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				passphraseSvc,
				payloadSerdeSvc,
				oldPayloadDecryptor,
				newPayloadEncryptor,
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

			passphraseSvc := passphrase.NewService()
			payloadSerdeSvc := payload.NewSerdeService(b64Svc)

			rsaSvc := rsa.NewRsaService(osExecutor)
			contentSvc := content.NewV1Service(b64Svc, aesSvc)
			passphraseDecrypter := passphrase.NewDecryptionRsaPKCS1v15Service(
				privKey,
				rsaSvc,
			)
			oldPayloadDecryptor := payload.NewDecryptionService(passphraseDecrypter, contentSvc)

			passphraseEncrypter := passphrase.NewEncryptionRsaPKCS1v15Service(rsaSvc, &privKey.PublicKey)
			newPayloadEncryptor := payload.NewEncryptionService(passphraseEncrypter, contentSvc)

			tfSvc := terraform.NewService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)
			actualReturn, actualErr := tfEncMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				passphraseSvc,
				payloadSerdeSvc,
				oldPayloadDecryptor,
				newPayloadEncryptor,
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

			passphraseSvc := passphrase.NewService()
			payloadSerdeSvc := payload.NewSerdeService(b64Svc)

			rsaSvc := rsa.NewRsaService(osExecutor)
			contentSvc := content.NewV1Service(b64Svc, aesSvc)
			passphraseDecrypter := passphrase.NewDecryptionRsaPKCS1v15Service(
				privKey,
				rsaSvc,
			)
			oldPayloadDecryptor := payload.NewDecryptionService(passphraseDecrypter, contentSvc)

			passphraseEncrypter := passphrase.NewEncryptionRsaPKCS1v15Service(rsaSvc, &privKey.PublicKey)
			newPayloadEncryptor := payload.NewEncryptionService(passphraseEncrypter, contentSvc)

			tfSvc := terraform.NewService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)
			actualReturn, actualErr := tfEncMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				passphraseSvc,
				payloadSerdeSvc,
				oldPayloadDecryptor,
				newPayloadEncryptor,
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

			passphraseSvc := passphrase.NewService()
			payloadSerdeSvc := payload.NewSerdeService(b64Svc)

			rsaSvc := rsa.NewRsaService(osExecutor)
			contentSvc := content.NewV1Service(b64Svc, aesSvc)
			passphraseDecrypter := passphrase.NewDecryptionRsaPKCS1v15Service(
				privKey,
				rsaSvc,
			)
			oldPayloadDecryptor := payload.NewDecryptionService(passphraseDecrypter, contentSvc)

			passphraseEncrypter := passphrase.NewEncryptionRsaPKCS1v15Service(rsaSvc, &privKey.PublicKey)
			newPayloadEncryptor := payload.NewEncryptionService(passphraseEncrypter, contentSvc)

			tfSvc := terraform.NewService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)
			actualReturn, actualErr := tfEncMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				passphraseSvc,
				payloadSerdeSvc,
				oldPayloadDecryptor,
				newPayloadEncryptor,
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

			passphraseSvc := passphrase.NewService()
			payloadSerdeSvc := payload.NewSerdeService(b64Svc)

			rsaSvc := rsa.NewRsaService(osExecutor)
			contentSvc := content.NewV1Service(b64Svc, aesSvc)
			passphraseDecrypter := passphrase.NewDecryptionRsaPKCS1v15Service(
				privKey,
				rsaSvc,
			)
			oldPayloadDecryptor := payload.NewDecryptionService(passphraseDecrypter, contentSvc)

			passphraseEncrypter := passphrase.NewEncryptionRsaPKCS1v15Service(rsaSvc, &privKey.PublicKey)
			newPayloadEncryptor := payload.NewEncryptionService(passphraseEncrypter, contentSvc)

			tfSvc := terraform.NewService()
			tfEncMigrationSvc := NewTerraformEncryptionMigrationService(tfSvc)
			actualReturn, actualErr := tfEncMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclParserArg,
				hclBytesArg,
				passphraseSvc,
				payloadSerdeSvc,
				oldPayloadDecryptor,
				newPayloadEncryptor,
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
			" and succeeds to encrypt and serialize payload "+
			"it returns AST with modified resources",
		func(t *testing.T) {
			t.Parallel()

			tfSvc := terraform.NewService()
			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			osExecutor := ostest.NewFakeOsExecutor(t)
			b64Svc := base64.NewBase64Service()
			rsaSvc := rsa.NewRsaService(osExecutor)
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			contentSvc := content.NewV1Service(b64Svc, aesSvc)
			passphraseSvc := passphrase.NewService()

			generatedPassphrase, err := passphraseSvc.GeneratePassphrase(32)
			require.Nil(t, err)

			payloadInstance := payload.NewPayload(
				header.NewHeader(),
				generatedPassphrase,
				content.NewContent(
					[]byte("mysecret!"),
				),
			)

			passphraseDecrypter := passphrase.NewDecryptionRsaPKCS1v15Service(
				privKey,
				rsaSvc,
			)
			oldPayloadDecryptor := payload.NewDecryptionService(passphraseDecrypter, contentSvc)

			passphraseEncrypter := passphrase.NewEncryptionRsaPKCS1v15Service(rsaSvc, &privKey.PublicKey)
			newPayloadEncryptor := payload.NewEncryptionService(passphraseEncrypter, contentSvc)

			payloadSerdeSvc := payload.NewSerdeService(b64Svc)

			encPayload, err := newPayloadEncryptor.Encrypt(payloadInstance)
			require.Nil(t, err)

			serializedPayloadJSON, err := payloadSerdeSvc.Serialize(encPayload)

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
				passphraseSvc,
				payloadSerdeSvc,
				oldPayloadDecryptor,
				newPayloadEncryptor,
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
