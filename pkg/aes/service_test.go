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

package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"

	"github.com/palantir/stacktrace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/pkcs7/test"
)

func TestNewAesService(t *testing.T) {
	t.Run(
		"it creates new aes Service with specified 'pkcs7Service'",
		func(t *testing.T) {
			t.Parallel()

			pkcs7Svc := pkcs7.NewPkcs7Service()

			actual := NewAesService(pkcs7Svc)

			assert.IsType(t, actual, &Service{})
			assert.Equal(t, actual.pkcs7Service, pkcs7Svc)
		},
	)
}

func TestAesService_EncryptCBC(t *testing.T) {
	t.Run(
		"when pkcs7 padding fails, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			mockPkcs7Service := &test.MockPkcs7Service{}
			mockPkcs7Service.Test(t)

			plaintextArg := []byte("abcdefgh")

			fakeError := errors.New("pad")

			mockPkcs7Service.On(
				"Pad",
				plaintextArg,
				aesCBCblockSize,
			).Return(nil, fakeError)

			aesSvc := NewAesService(mockPkcs7Service)

			keyArg := []byte("mypassphrase")
			actualReturn, actualErr := aesSvc.EncryptCBC(keyArg, plaintextArg)

			require.Nil(t, actualReturn)
			assert.Equal(t, fakeError, stacktrace.RootCause(actualErr))

			mockPkcs7Service.AssertExpectations(t)
		},
	)

	t.Run(
		"when pkcs7 padded text is not in multiples of aes blocksize, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			mockPkcs7Service := &test.MockPkcs7Service{}
			mockPkcs7Service.Test(t)

			keyArg := []byte("mypassphrase")
			plaintextArg := []byte("abcdefgh")

			// NOTE: `aesCBCblockSize` is 16,
			// so padded text must be 17 to not be of multiples of aes blocksize.
			fakePaddedPlaintext := []byte("12345678901234567")

			mockPkcs7Service.On(
				"Pad",
				plaintextArg,
				aesCBCblockSize,
			).Return(fakePaddedPlaintext, nil)

			aesSvc := NewAesService(mockPkcs7Service)

			actualReturn, actualErr := aesSvc.EncryptCBC(keyArg, plaintextArg)

			require.Nil(t, actualReturn)
			assert.Equal(t, errInvalidBlockSize, actualErr)

			mockPkcs7Service.AssertExpectations(t)
		},
	)

	t.Run(
		"when 'key' is not of equal in length to 16 block size, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			// NOTE: aesCBCblockSize is 16, so invalid passphrase would be 9.
			keyArg := []byte("123456789")
			plaintextArg := []byte("abcdefgh")

			aesSvc := NewAesService(
				pkcs7.NewPkcs7Service(),
			)

			actualReturn, actualErr := aesSvc.EncryptCBC(keyArg, plaintextArg)

			require.Nil(t, actualReturn)
			assert.Equal(t, actualErr, errInvalidCBCKeySize)
		},
	)

	t.Run(
		"when key is of block size 16 and padded pkcs7 plain text is multiples of block size 16, it returns encrypted ciphertext",
		func(t *testing.T) {
			t.Parallel()

			keyArg := []byte("1234567890123456")
			plaintextArg := []byte("abcdefgh")

			aesSvc := NewAesService(
				pkcs7.NewPkcs7Service(),
			)

			actualReturn, actualEr := aesSvc.EncryptCBC(keyArg, plaintextArg)

			require.Nil(t, actualEr)

			assert.NotContains(t, plaintextArg, actualReturn)
		},
	)
}

func TestService_DecryptCBC(t *testing.T) {
	t.Run(
		"when 'key' is not of equal in length to 16 block size, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			// NOTE: aesCBCblockSize is 16, so invalid passphrase would be 9.
			keyArg := []byte("123456789")
			ciphertextArg := []byte("1a2b3c4d5e6f7g8h")

			aesSvc := NewAesService(
				pkcs7.NewPkcs7Service(),
			)

			actualReturn, actualErr := aesSvc.DecryptCBC(keyArg, ciphertextArg)

			require.Nil(t, actualReturn)
			assert.Equal(t, errInvalidCBCKeySize, stacktrace.RootCause(actualErr))
		},
	)

	t.Run(
		"when 'key' is 16 block size and 'ciphertext' is shorter than the 16 block size, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			keyArg := []byte("1234567890123456")
			// NOTE: Noticeably shorter than the `keyArg`.
			ciphertextArg := []byte("1ab2")

			aesSvc := NewAesService(
				pkcs7.NewPkcs7Service(),
			)

			actualReturn, actualErr := aesSvc.DecryptCBC(keyArg, ciphertextArg)

			require.Nil(t, actualReturn)
			assert.Equal(t, errTooShortCiphertext, stacktrace.RootCause(actualErr))
		},
	)

	t.Run(
		"when 'key' is block 16 size and 'ciphertext''s padded encrypted content is not of multiple of block size, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			aesSvc := NewAesService(
				pkcs7.NewPkcs7Service(),
			)

			keyArg := []byte("1234567890123456")
			plaintext := []byte("1a2b3c4d")
			ciphertext, err := aesSvc.EncryptCBC(keyArg, plaintext)
			require.Nil(t, err)

			var cipherTextArg []byte

			cipherTextArg = append(
				cipherTextArg,
				ciphertext[:aesCBCblockSize]...,
			)

			cipherTextArg = append(
				cipherTextArg,
				ciphertext[aesCBCblockSize:]...,
			)

			// NOTE: Corrupt the `ciphertextArg` to have
			// inconsistent (not multiples of) padded ciphertext.
			cipherTextArg = append(
				cipherTextArg,
				0x01,
				0x02,
				0x03,
				0x04,
				0x05,
				0x06,
				0x07,
			)

			actualReturn, actualErr := aesSvc.DecryptCBC(keyArg, cipherTextArg)

			require.Nil(t, actualReturn)
			assert.Equal(t, errInvalidBlockSize, stacktrace.RootCause(actualErr))
		},
	)

	t.Run(
		"when 'key' is block 16 size and 'ciphertext' pkcs7 unpadding fails, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			aesSvc := NewAesService(
				pkcs7.NewPkcs7Service(),
			)

			keyArg := []byte("1234567890123456")
			plaintext := []byte("1a2b3c4d")
			ciphertextArg, err := aesSvc.EncryptCBC(keyArg, plaintext)
			require.Nil(t, err)

			mockPkcs7Service := &test.MockPkcs7Service{}
			mockPkcs7Service.Test(t)

			fakeError := errors.New("unpad")

			mockPkcs7Service.On(
				"Unpad",
				ciphertextArg[aesCBCblockSize:],
				aesCBCblockSize,
			).Return(nil, fakeError)

			aesSvc = NewAesService(
				mockPkcs7Service,
			)

			actualReturn, actualErr := aesSvc.DecryptCBC(keyArg, ciphertextArg)

			require.Nil(t, actualReturn)

			assert.Equal(t, fakeError, stacktrace.RootCause(actualErr))

			mockPkcs7Service.AssertExpectations(t)
		},
	)

	t.Run(
		"when 'key' is shared from previous encryption run and 'ciphertext' is encrypted via aes CBC, it must decrypt it successfully and return plaintext",
		func(t *testing.T) {
			t.Parallel()

			pkcs7Svc := pkcs7.NewPkcs7Service()

			aesSvc := NewAesService(pkcs7Svc)

			keyArg := []byte("1234567890123456")
			plaintextArg := []byte("myplaintext")

			ciphertextArg, err := aesSvc.EncryptCBC(keyArg, plaintextArg)

			require.Nil(t, err)

			actualReturn, err := aesSvc.DecryptCBC(keyArg, ciphertextArg)

			require.Nil(t, err)

			assert.Equal(t, plaintextArg, actualReturn)
		},
	)
}

func TestAesService_EncryptGCM(t *testing.T) {
	t.Run(
		"when 'key' is not of equal in length to 32 block size, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			// NOTE: Invalid key size of 9
			keyArg := []byte("123456789")
			plaintextArg := []byte("abcdefgh")

			aesSvc := NewAesService(
				pkcs7.NewPkcs7Service(),
			)

			actualReturn, actualErr := aesSvc.EncryptGCM(keyArg, plaintextArg)

			require.Nil(t, actualReturn)
			assert.Equal(t, actualErr, errInvalidGCMKeySize)
		},
	)

	t.Run(
		"when key is of block size 32 and plaintext is empty, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			keyArg := []byte("12345678901234567890123456789012")
			plaintextArg := []byte("")

			aesSvc := NewAesService(
				pkcs7.NewPkcs7Service(),
			)

			actualReturn, actualErr := aesSvc.EncryptGCM(keyArg, plaintextArg)

			require.Nil(t, actualReturn)

			assert.Equal(t, errInvalidEmptyPayload, actualErr)
		},
	)

	t.Run(
		"when key is of block size 32 and plaintext is not empty, "+
			"it returns ciphertext that is AES 256-GCM decryptable",
		func(t *testing.T) {
			t.Parallel()

			keyArg := []byte("12345678901234567890123456789012")
			plaintextArg := []byte("mysecret")

			aesSvc := NewAesService(
				pkcs7.NewPkcs7Service(),
			)

			actualReturn, actualErr := aesSvc.EncryptGCM(keyArg, plaintextArg)

			require.Nil(t, actualErr)
			assert.NotContains(t, string(plaintextArg), string(actualReturn))

			actualNonce := actualReturn[:aesGCMNonceSize]
			actualCiphertext := actualReturn[aesGCMNonceSize:]

			block, err := aes.NewCipher(keyArg)
			require.Nil(t, err)

			mode, err := cipher.NewGCM(block)

			plaintext, err := mode.Open(
				nil,
				actualNonce,
				actualCiphertext,
				nil,
			)

			assert.Equal(t, plaintextArg, plaintext)
		},
	)
}

func TestAesService_DecryptGCM(t *testing.T) {
	t.Run(
		"when 'key' is not of equal in length to 32 block size, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			// NOTE: Invalid key size of 9
			keyArg := []byte("123456789")
			ciphertextArg := []byte("1a2b3c4d")

			aesSvc := NewAesService(
				pkcs7.NewPkcs7Service(),
			)

			actualReturn, actualErr := aesSvc.DecryptGCM(keyArg, ciphertextArg)

			require.Nil(t, actualReturn)
			assert.Equal(t, actualErr, errInvalidGCMKeySize)
		},
	)

	t.Run(
		"when key is of block size 32 and ciphertext is empty, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			keyArg := []byte("12345678901234567890123456789012")
			ciphertextArg := []byte("")

			aesSvc := NewAesService(
				pkcs7.NewPkcs7Service(),
			)

			actualReturn, actualErr := aesSvc.DecryptGCM(keyArg, ciphertextArg)

			require.Nil(t, actualReturn)

			assert.Equal(t, errInvalidEmptyPayload, actualErr)
		},
	)

	t.Run(
		"when key is of block size 32 and ciphertext is not empty, "+
			"but does not contain nonce in first 12 bytes, "+
			"it returns error",
		func(t *testing.T) {
			t.Parallel()

			keyArg := []byte("12345678901234567890123456789012")
			plaintext := []byte("mysecret")

			aesSvc := NewAesService(
				pkcs7.NewPkcs7Service(),
			)

			ciphertextWithNonce, err := aesSvc.EncryptGCM(keyArg, plaintext)
			require.Nil(t, err)

			ciphertextOnly := ciphertextWithNonce[aesGCMNonceSize:]

			actualReturn, actualErr := aesSvc.DecryptGCM(keyArg, ciphertextOnly)

			require.Nil(t, actualReturn)
			assert.Contains(t, actualErr.Error(), "unable to decrypt AES-GCM ciphertext")
		},
	)

	t.Run(
		"when key is of block size 32 and ciphertext is not empty and contains once, "+
			"it returns plaintext",
		func(t *testing.T) {
			t.Parallel()

			keyArg := []byte("12345678901234567890123456789012")
			plaintext := []byte("mysecret")

			aesSvc := NewAesService(
				pkcs7.NewPkcs7Service(),
			)

			ciphertextWithNonce, err := aesSvc.EncryptGCM(keyArg, plaintext)
			require.Nil(t, err)

			actualReturn, actualErr := aesSvc.DecryptGCM(keyArg, ciphertextWithNonce)

			require.Nil(t, actualErr)
			assert.Equal(t, string(plaintext), string(actualReturn))
		},
	)
}
