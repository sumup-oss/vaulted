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

package passphrase

import (
	"crypto/rand"
	stdRsa "crypto/rsa"
	"errors"
	"testing"

	"github.com/palantir/stacktrace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sumup-oss/go-pkgs/os"
	"github.com/sumup-oss/go-pkgs/os/ostest"
	"github.com/sumup-oss/vaulted/pkg/base64"
	testB64 "github.com/sumup-oss/vaulted/pkg/base64/test"
	"github.com/sumup-oss/vaulted/pkg/rsa"
	testRsa "github.com/sumup-oss/vaulted/pkg/rsa/test"
)

func TestNewEncryptedPassphraseService(t *testing.T) {
	t.Run(
		"it creates a new encrypted passphrase with 'base64Service' and 'rsaService' arguments",
		func(t *testing.T) {
			t.Parallel()

			base64Service := base64.NewBase64Service()
			rsaService := rsa.NewRsaService(&os.RealOsExecutor{})

			actual := NewEncryptedPassphraseService(base64Service, rsaService)

			assert.Equal(t, actual.base64Service, base64Service)
			assert.Equal(t, actual.rsaService, rsaService)
		},
	)
}

func TestEncryptedPassphraseService_Serialize(t *testing.T) {
	t.Run(
		"when base64 encoding of 'encryptedPassphrase' fails, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			mockBase64Svc := &testB64.MockBase64Service{}

			encPassphrase := NewEncryptedPassphrase(
				[]byte("1a2b3c4d"),
			)
			fakeErr := errors.New("serializeErr")

			mockBase64Svc.On(
				"Serialize",
				encPassphrase.Ciphertext,
			).Return(nil, fakeErr)

			svc := NewEncryptedPassphraseService(
				mockBase64Svc,
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)

			actualReturn, actualErr := svc.Serialize(encPassphrase)

			require.Nil(t, actualReturn)
			assert.Equal(t, fakeErr, actualErr)

			mockBase64Svc.AssertExpectations(t)
		},
	)

	t.Run(
		"when base64 encoding of 'encryptedPassphrase' succeeds, it returns it base64 encoded",
		func(t *testing.T) {
			t.Parallel()

			b64Service := base64.NewBase64Service()
			svc := NewEncryptedPassphraseService(
				b64Service,
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)

			encryptedPassphrase := NewEncryptedPassphrase(
				[]byte(
					"1a2b3c4d"),
			)

			expectedReturn, err := b64Service.Serialize(encryptedPassphrase.Ciphertext)
			require.Nil(t, err)

			actualReturn, actualErr := svc.Serialize(encryptedPassphrase)
			require.Nil(t, actualErr)

			assert.Equal(t, expectedReturn, actualReturn)
		},
	)
}

func TestEncryptedPassphraseService_Deserialize(t *testing.T) {
	t.Run(
		"when base64 decoding of 'encoded' fails, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			mockBase64Svc := &testB64.MockBase64Service{}

			encodedArg := []byte("1a2b3c4d")
			fakeErr := errors.New("serializeErr")

			mockBase64Svc.On(
				"Deserialize",
				encodedArg,
			).Return(nil, fakeErr)

			svc := NewEncryptedPassphraseService(
				mockBase64Svc,
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)

			actualReturn, actualErr := svc.Deserialize(encodedArg)

			require.Nil(t, actualReturn)
			assert.Contains(
				t,
				actualErr.Error(),
				"failed to deserialize base64 encoded encrypted passphrase",
			)

			mockBase64Svc.AssertExpectations(t)
		},
	)

	t.Run(
		"when base64 decoding of 'encoded' succeeds, it returns it encrypted passphrase",
		func(t *testing.T) {
			t.Parallel()

			b64Service := base64.NewBase64Service()
			svc := NewEncryptedPassphraseService(
				b64Service,
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)

			ciphertext := []byte("1a2b3c4d")
			encryptedPassphrase := NewEncryptedPassphrase(ciphertext)

			encoded, err := b64Service.Serialize(encryptedPassphrase.Ciphertext)
			require.Nil(t, err)

			actualReturn, actualErr := svc.Deserialize(encoded)
			require.Nil(t, actualErr)

			assert.Equal(t, ciphertext, actualReturn.Ciphertext)
		},
	)
}

func TestEncryptedPassphraseService_Encrypt(t *testing.T) {
	t.Run(
		"when 'passphrase' content pkcs#1 v1.5 encryption fails, it returns error",
		func(t *testing.T) {
			t.Parallel()

			mockRsaSvc := &testRsa.MockRsaService{}
			mockRsaSvc.Test(t)

			fakeError := errors.New("fakencrypterror")

			svc := NewEncryptedPassphraseService(
				base64.NewBase64Service(),
				mockRsaSvc,
			)

			pubkeyArg := &stdRsa.PublicKey{}
			passphraseArg := newPassphrase([]byte("1234"))

			mockRsaSvc.On(
				"EncryptPKCS1v15",
				rand.Reader,
				pubkeyArg,
				[]byte(passphraseArg.Content),
			).Return(nil, fakeError)

			actualReturn, actualErr := svc.Encrypt(pubkeyArg, passphraseArg)

			require.Nil(t, actualReturn)
			assert.Equal(t,  fakeError, stacktrace.RootCause(actualErr))

			mockRsaSvc.AssertExpectations(t)
		},
	)

	t.Run(
		"when 'passphrase' content pkcs#1 v1.5 encryption succeeds, it returns encrypted passphrase",
		func(t *testing.T) {
			t.Parallel()

			mockRsaSvc := &testRsa.MockRsaService{}
			mockRsaSvc.Test(t)

			fakeEncryptedPassphrase := NewEncryptedPassphrase([]byte("1a2b3c4d"))

			pubkeyArg := &stdRsa.PublicKey{}
			passphraseArg := newPassphrase([]byte("1234"))

			mockRsaSvc.On(
				"EncryptPKCS1v15",
				rand.Reader,
				pubkeyArg,
				[]byte(passphraseArg.Content),
			).Return(
				[]byte(fakeEncryptedPassphrase.Ciphertext),
				nil,
			)

			svc := NewEncryptedPassphraseService(
				base64.NewBase64Service(),
				mockRsaSvc,
			)

			actualReturn, actualErr := svc.Encrypt(pubkeyArg, passphraseArg)

			require.Nil(t, actualErr)
			assert.Equal(t, fakeEncryptedPassphrase, actualReturn)

			mockRsaSvc.AssertExpectations(t)
		},
	)
}

func TestEncryptedPassphraseService_Decrypt(t *testing.T) {
	t.Run(
		"when 'ciphertext' content pkcs#1 v1.5 decryption fails, it returns error",
		func(t *testing.T) {
			t.Parallel()

			mockRsaSvc := &testRsa.MockRsaService{}
			mockRsaSvc.Test(t)

			fakeError := errors.New("fakencrypterror")

			svc := NewEncryptedPassphraseService(
				base64.NewBase64Service(),
				mockRsaSvc,
			)

			privkeyArg := &stdRsa.PrivateKey{}
			encryptedPassphraseArg := NewEncryptedPassphrase([]byte("1a2b3c4d"))

			mockRsaSvc.On(
				"DecryptPKCS1v15",
				rand.Reader,
				privkeyArg,
				[]byte(encryptedPassphraseArg.Ciphertext),
			).Return(nil, fakeError)

			actualReturn, actualErr := svc.Decrypt(privkeyArg, encryptedPassphraseArg)

			require.Nil(t, actualReturn)
			assert.Equal(t, fakeError, stacktrace.RootCause(actualErr))

			mockRsaSvc.AssertExpectations(t)
		},
	)

	t.Run(
		"when 'passphrase' content pkcs#1 v1.5 decryption succeeds, it returns passphrase",
		func(t *testing.T) {
			t.Parallel()

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			svc := NewEncryptedPassphraseService(
				base64.NewBase64Service(),
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)

			passphrase, err := svc.GeneratePassphrase(16)
			require.Nil(t, err)

			encryptedPasshraseArg, err := svc.Encrypt(&privKey.PublicKey, passphrase)
			require.Nil(t, err)

			actualReturn, actualErr := svc.Decrypt(privKey, encryptedPasshraseArg)

			require.Nil(t, actualErr)
			assert.Equal(t, passphrase, actualReturn)
		},
	)
}

func TestEncryptedPassphraseService_GeneratePassphrase(t *testing.T) {
	t.Run(
		"when generating a random buffer fails, it returns an error",
		func(t *testing.T) {
			lengthArg := 12

			calledRandReadErr := errors.New("fakeerror")

			realRandRead := randRead

			defer func() {
				randRead = realRandRead
			}()

			randRead = func(b []byte) (n int, err error) {
				return 0, calledRandReadErr
			}

			osExecutor := ostest.NewFakeOsExecutor(t)
			svc := NewEncryptedPassphraseService(
				base64.NewBase64Service(),
				rsa.NewRsaService(osExecutor),
			)

			actualReturn, actualErr := svc.GeneratePassphrase(lengthArg)
			require.Nil(t, actualReturn)
			assert.Equal(t, calledRandReadErr, stacktrace.RootCause(actualErr))
		},
	)

	t.Run(
		"when generating a random buffer succeeds, it generates a passphrase up to 'length'",
		func(t *testing.T) {
			lengthArg := 12

			osExecutor := ostest.NewFakeOsExecutor(t)
			svc := NewEncryptedPassphraseService(
				base64.NewBase64Service(),
				rsa.NewRsaService(osExecutor),
			)

			actual, err := svc.GeneratePassphrase(lengthArg)

			require.Nil(t, err)
			assert.IsType(t, actual, &Passphrase{})
			assert.Equal(t, lengthArg, len(actual.Content))
		},
	)
}
