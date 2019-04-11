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

package content

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sumup-oss/go-pkgs/os/ostest"
	"github.com/sumup-oss/vaulted/pkg/aes"
	testAes "github.com/sumup-oss/vaulted/pkg/aes/test"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/base64/test"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/rsa"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
)

func TestNewLegacyEncryptedContentService(t *testing.T) {
	t.Run(
		"it creates a new LegacyEncryptedContentService with 'base64Service' and 'aesService' arguments",
		func(t *testing.T) {
			t.Parallel()

			base64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(
				pkcs7.NewPkcs7Service(),
			)

			actual := NewLegacyEncryptedContentService(
				base64Svc,
				aesSvc,
			)

			assert.Equal(t, base64Svc, actual.base64Service)
			assert.Equal(t, aesSvc, actual.aesService)
		},
	)
}

func TestEncryptedContentService_Serialize(t *testing.T) {
	t.Run(
		"when base64 encoding of 'encryptedContent' fails, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			mockBase64Svc := &test.MockBase64Service{}

			encContent := NewEncryptedContent(
				[]byte("1a2b3c4d"),
			)
			fakeErr := errors.New("serializeErr")

			mockBase64Svc.On(
				"Serialize",
				encContent.Ciphertext,
			).Return(nil, fakeErr)

			svc := NewLegacyEncryptedContentService(
				mockBase64Svc,
				aes.NewAesService(
					pkcs7.NewPkcs7Service(),
				),
			)

			actualReturn, actualErr := svc.Serialize(encContent)

			require.Nil(t, actualReturn)
			assert.Equal(t, fakeErr, actualErr)

			mockBase64Svc.AssertExpectations(t)
		},
	)

	t.Run(
		"when base64 encoding of 'encryptedContent' succeeds, it returns it base64 encoded",
		func(t *testing.T) {
			t.Parallel()

			b64Service := base64.NewBase64Service()
			svc := NewLegacyEncryptedContentService(
				base64.NewBase64Service(),
				aes.NewAesService(
					pkcs7.NewPkcs7Service(),
				),
			)

			encryptedContent := NewEncryptedContent(
				[]byte(
					"1a2b3c4d"),
			)

			expectedReturn, err := b64Service.Serialize(encryptedContent.Ciphertext)
			require.Nil(t, err)

			actualReturn, actualErr := svc.Serialize(encryptedContent)
			require.Nil(t, actualErr)

			assert.Equal(t, expectedReturn, actualReturn)
		},
	)
}

func TestEncryptedContentService_Deserialize(t *testing.T) {
	t.Run(
		"when base64 decoding of 'encoded' fails, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			mockBase64Svc := &test.MockBase64Service{}

			encodedArg := []byte("1a2b3c4d")
			fakeErr := errors.New("serializeErr")

			mockBase64Svc.On(
				"Deserialize",
				encodedArg,
			).Return(nil, fakeErr)

			svc := NewLegacyEncryptedContentService(
				mockBase64Svc,
				aes.NewAesService(
					pkcs7.NewPkcs7Service(),
				),
			)

			actualReturn, actualErr := svc.Deserialize(encodedArg)

			require.Nil(t, actualReturn)
			assert.Contains(
				t,
				actualErr.Error(),
				"failed to deserialize base64 encoded encrypted content",
			)

			mockBase64Svc.AssertExpectations(t)
		},
	)

	t.Run(
		"when base64 decoding of 'encoded' succeeds, it returns it encrypted content",
		func(t *testing.T) {
			t.Parallel()

			b64Service := base64.NewBase64Service()
			svc := NewLegacyEncryptedContentService(
				b64Service,
				aes.NewAesService(
					pkcs7.NewPkcs7Service(),
				),
			)

			ciphertext := []byte("1a2b3c4d")
			encryptedPassphrase := NewEncryptedContent(ciphertext)

			encoded, err := b64Service.Serialize(encryptedPassphrase.Ciphertext)
			require.Nil(t, err)

			actualReturn, actualErr := svc.Deserialize(encoded)
			require.Nil(t, actualErr)

			assert.Equal(t, ciphertext, actualReturn.Ciphertext)
		},
	)
}

func TestEncryptedContentService_Encrypt(t *testing.T) {
	t.Run(
		"when encryption of 'content' fails, it returns error",
		func(t *testing.T) {
			t.Parallel()

			b64Svc := base64.NewBase64Service()
			osExecutor := ostest.NewFakeOsExecutor(t)

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			passphraseArg, err := encPassphraseSvc.GeneratePassphrase(16)
			require.Nil(t, err)

			contentArg := NewContent(
				[]byte("hello"),
			)

			fakeErr := errors.New("fakeEncryptError")

			mockAesSvc := &testAes.MockAesService{}
			mockAesSvc.Test(t)

			mockAesSvc.On(
				"EncryptCBC",
				passphraseArg.Content,
				[]byte(
					contentArg.Plaintext,
				),
			).Return(
				nil,
				fakeErr,
			)

			encryptedContentSvc := NewLegacyEncryptedContentService(
				b64Svc,
				mockAesSvc,
			)

			actualReturn, actualErr := encryptedContentSvc.Encrypt(
				passphraseArg,
				contentArg,
			)

			require.Nil(t, actualReturn)

			assert.Contains(t, actualErr.Error(), fakeErr.Error())

			mockAesSvc.AssertExpectations(t)
		},
	)

	t.Run(
		"when encryption of 'content' succeeds, it returns encrypted content",
		func(t *testing.T) {
			t.Parallel()

			b64Svc := base64.NewBase64Service()
			osExecutor := ostest.NewFakeOsExecutor(t)

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			passphraseArg, err := encPassphraseSvc.GeneratePassphrase(16)
			require.Nil(t, err)

			contentArg := NewContent(
				[]byte("hello"),
			)

			aesSvc := aes.NewAesService(
				pkcs7.NewPkcs7Service(),
			)

			encryptedContentSvc := NewLegacyEncryptedContentService(
				b64Svc,
				aesSvc,
			)

			actualReturn, actualErr := encryptedContentSvc.Encrypt(
				passphraseArg,
				contentArg,
			)

			require.Nil(t, actualErr)

			assert.NotContains(
				t,
				string(
					actualReturn.Ciphertext,
				),
				string(
					contentArg.Plaintext,
				),
			)

			assert.IsType(
				t,
				actualReturn,
				&EncryptedContent{},
			)
		},
	)
}

func TestEncryptedContentService_Decrypt(t *testing.T) {
	t.Run(
		"when decryption of 'encryptedContent' fails, it returns error",
		func(t *testing.T) {
			t.Parallel()

			b64Svc := base64.NewBase64Service()
			osExecutor := ostest.NewFakeOsExecutor(t)

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			passphraseArg, err := encPassphraseSvc.GeneratePassphrase(16)
			require.Nil(t, err)

			encryptedContentArg := NewEncryptedContent(
				[]byte("1a2b3c4"),
			)

			fakeErr := errors.New("fakeDecryptError")

			mockAesSvc := &testAes.MockAesService{}
			mockAesSvc.Test(t)

			mockAesSvc.On(
				"DecryptCBC",
				passphraseArg.Content,
				[]byte(
					encryptedContentArg.Ciphertext,
				),
			).Return(
				nil,
				fakeErr,
			)

			encryptedContentSvc := NewLegacyEncryptedContentService(
				b64Svc,
				mockAesSvc,
			)

			actualReturn, actualErr := encryptedContentSvc.Decrypt(
				passphraseArg,
				encryptedContentArg,
			)

			require.Nil(t, actualReturn)

			assert.Contains(t, actualErr.Error(), fakeErr.Error())

			mockAesSvc.AssertExpectations(t)
		},
	)

	t.Run(
		"when decryption of 'encryptedContent' succeeds, it returns decrypted content",
		func(t *testing.T) {
			t.Parallel()

			aesSvc := aes.NewAesService(
				pkcs7.NewPkcs7Service(),
			)

			b64Svc := base64.NewBase64Service()
			osExecutor := ostest.NewFakeOsExecutor(t)

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(osExecutor),
			)
			passphraseArg, err := encPassphraseSvc.GeneratePassphrase(16)
			require.Nil(t, err)

			contentArg := NewContent(
				[]byte("hello"),
			)

			encryptedContentSvc := NewLegacyEncryptedContentService(
				b64Svc,
				aesSvc,
			)

			encryptedContentArg, err := encryptedContentSvc.Encrypt(
				passphraseArg,
				contentArg,
			)
			require.Nil(t, err)

			actualReturn, actualErr := encryptedContentSvc.Decrypt(
				passphraseArg,
				encryptedContentArg,
			)

			require.Nil(t, actualErr)

			assert.Equal(t, contentArg.Plaintext, actualReturn.Plaintext)
		},
	)
}
