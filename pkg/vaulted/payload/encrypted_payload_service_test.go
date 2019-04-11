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

package payload

import (
	"crypto/rand"
	stdRsa "crypto/rsa"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sumup-oss/go-pkgs/os"
	"github.com/sumup-oss/go-pkgs/os/ostest"
	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/rsa"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	testContent "github.com/sumup-oss/vaulted/pkg/vaulted/content/test"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	testHeader "github.com/sumup-oss/vaulted/pkg/vaulted/header/test"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
	testPassphrase "github.com/sumup-oss/vaulted/pkg/vaulted/passphrase/test"
)

func TestNewEncryptionPayloadService(t *testing.T) {
	t.Run(
		"it creates a new encrypted content service with specified 'HeaderService', 'EncryptedPassphraseService' and 'EncryptedContentService'",
		func(t *testing.T) {
			t.Parallel()

			headerServiceArg := header.NewHeaderService()
			encryptedPassphraseServiceArg := passphrase.NewEncryptedPassphraseService(
				base64.NewBase64Service(),
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)
			encryptedContentServiceArg := content.NewLegacyEncryptedContentService(
				base64.NewBase64Service(),
				aes.NewAesService(
					pkcs7.NewPkcs7Service(),
				),
			)

			actual := NewEncryptedPayloadService(
				headerServiceArg,
				encryptedPassphraseServiceArg,
				encryptedContentServiceArg,
			)

			assert.Equal(t, headerServiceArg, actual.headerService)
			assert.Equal(t, encryptedPassphraseServiceArg, actual.encryptedPassphraseService)
			assert.Equal(t, encryptedContentServiceArg, actual.encryptedContentService)
		},
	)
}

func TestEncryptedPayloadService_Constants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "::", EncryptionPayloadSeparator)
}

func TestEncryptedPayloadService_Serialize(t *testing.T) {
	t.Run(
		"when serializing the 'header', 'encryptedPassphrase' and "+
			"'encryptedContent' from 'encryptedPayload', "+
			"but serializing 'header' fails, "+
			"it returns an error",
		func(t *testing.T) {
			t.Parallel()

			mockHeaderSvc := &testHeader.MockHeaderService{}
			mockHeaderSvc.Test(t)

			encryptedPassphrase := passphrase.NewEncryptedPassphrase(
				[]byte("1a2b3c4d"),
			)
			encryptedContent := content.NewEncryptedContent(
				[]byte("1a2b3c4d"),
			)

			header := header.NewHeader()
			encryptedPayloadArg := NewEncryptedPayload(
				header,
				encryptedPassphrase,
				encryptedContent,
			)

			fakeError := errors.New("headerSvcError")
			mockHeaderSvc.On("Serialize", header).Return(nil, fakeError)

			b64Service := base64.NewBase64Service()

			svc := NewEncryptedPayloadService(
				mockHeaderSvc,
				passphrase.NewEncryptedPassphraseService(
					b64Service,
					rsa.NewRsaService(&os.RealOsExecutor{}),
				),
				content.NewLegacyEncryptedContentService(
					b64Service,
					aes.NewAesService(
						pkcs7.NewPkcs7Service(),
					),
				),
			)

			actualReturn, actualErr := svc.Serialize(encryptedPayloadArg)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to serialize encrypted payload's header",
			)

			mockHeaderSvc.AssertExpectations(t)
		},
	)

	t.Run(
		"when serializing the 'header', 'encryptedPassphrase' and "+
			"'encryptedContent' from 'encryptedPayload', "+
			"but serializing 'encryptedPassphrase' fails, "+
			"it returns an error",
		func(t *testing.T) {
			t.Parallel()

			mockEncryptedPassphraseSvc := &testPassphrase.MockEncryptedPassphraseService{}
			mockEncryptedPassphraseSvc.Test(t)

			encryptedPassphrase := passphrase.NewEncryptedPassphrase(
				[]byte("1a2b3c4d"),
			)
			encryptedContent := content.NewEncryptedContent(
				[]byte("1a2b3c4d"),
			)

			headerArg := header.NewHeader()
			encryptedPayloadArg := NewEncryptedPayload(
				headerArg,
				encryptedPassphrase,
				encryptedContent,
			)

			fakeError := errors.New("encryptedPassphraseSvcError")
			mockEncryptedPassphraseSvc.On(
				"Serialize",
				encryptedPassphrase,
			).Return(nil, fakeError)

			b64Service := base64.NewBase64Service()

			svc := NewEncryptedPayloadService(
				header.NewHeaderService(),
				mockEncryptedPassphraseSvc,
				content.NewLegacyEncryptedContentService(
					b64Service,
					aes.NewAesService(
						pkcs7.NewPkcs7Service(),
					),
				),
			)

			actualReturn, actualErr := svc.Serialize(encryptedPayloadArg)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to serialize encrypted payload's encrypted passphrase",
			)

			mockEncryptedPassphraseSvc.AssertExpectations(t)
		},
	)

	t.Run(
		"when serializing the 'header', 'encryptedPassphrase' and "+
			"'encryptedContent' from 'encryptedPayload', "+
			"but serializing 'encryptedContent' fails, "+
			"it returns an error",
		func(t *testing.T) {
			t.Parallel()

			mockEncryptedContentSvc := &testContent.MockEncryptedContentService{}
			mockEncryptedContentSvc.Test(t)

			encryptedContent := content.NewEncryptedContent(
				[]byte("1a2b3c4d"),
			)

			fakeError := errors.New("encryptedContentSvcError")
			mockEncryptedContentSvc.On(
				"Serialize",
				encryptedContent,
			).Return(nil, fakeError)

			encryptedPassphrase := passphrase.NewEncryptedPassphrase(
				[]byte("1a2b3c4d"),
			)
			encryptedPayloadArg := NewEncryptedPayload(
				header.NewHeader(),
				encryptedPassphrase,
				encryptedContent,
			)

			b64Service := base64.NewBase64Service()

			svc := NewEncryptedPayloadService(
				header.NewHeaderService(),
				passphrase.NewEncryptedPassphraseService(
					b64Service,
					rsa.NewRsaService(&os.RealOsExecutor{}),
				),
				mockEncryptedContentSvc,
			)

			actualReturn, actualErr := svc.Serialize(encryptedPayloadArg)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to serialize encrypted payload's encrypted content",
			)

			mockEncryptedContentSvc.AssertExpectations(t)
		},
	)

	t.Run(
		"when serializing the 'header', 'encryptedPassphrase' and "+
			"'encryptedContent' from 'encryptedPayload', "+
			"and everything succeeds, it returns serialized content",
		func(t *testing.T) {
			t.Parallel()

			headerArg := header.NewHeader()
			encryptedPassphrase := passphrase.NewEncryptedPassphrase(
				[]byte("1a2b3c4d"),
			)
			encryptedContent := content.NewEncryptedContent(
				[]byte("1a2b3c4d"),
			)

			encryptedPayloadArg := NewEncryptedPayload(
				headerArg,
				encryptedPassphrase,
				encryptedContent,
			)

			b64Service := base64.NewBase64Service()

			headerSvc := header.NewHeaderService()
			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				b64Service,
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)

			encContentSvc := content.NewLegacyEncryptedContentService(
				b64Service,
				aes.NewAesService(
					pkcs7.NewPkcs7Service(),
				),
			)

			svc := NewEncryptedPayloadService(
				headerSvc,
				encPassphraseSvc,
				encContentSvc,
			)

			encodedHeader, err := headerSvc.Serialize(headerArg)
			require.Nil(t, err)

			encodedEncryptedPassphrase, err := encPassphraseSvc.Serialize(encryptedPassphrase)
			require.Nil(t, err)

			encodedEncryptedContent, err := encContentSvc.Serialize(encryptedContent)
			require.Nil(t, err)

			serializedReturn := fmt.Sprintf(
				"%s%s%s%s%s",
				encodedHeader,
				EncryptionPayloadSeparator,
				encodedEncryptedPassphrase,
				EncryptionPayloadSeparator,
				encodedEncryptedContent,
			)

			expectedReturn := []byte(serializedReturn)

			actualReturn, actualErr := svc.Serialize(encryptedPayloadArg)
			require.Nil(t, actualErr)

			assert.Equal(t, expectedReturn, actualReturn)
		},
	)
}

func TestEncryptedPayloadService_Deserialize(t *testing.T) {
	t.Run(
		"when 'encodedContent' is blank, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			b64ServiceArg := base64.NewBase64Service()

			headerServiceArg := header.NewHeaderService()
			encryptedPassphraseServiceArg := passphrase.NewEncryptedPassphraseService(
				b64ServiceArg,
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)
			encryptedContentServiceArg := content.NewLegacyEncryptedContentService(
				b64ServiceArg,
				aes.NewAesService(
					pkcs7.NewPkcs7Service(),
				),
			)

			encryptedPayloadSvc := NewEncryptedPayloadService(
				headerServiceArg,
				encryptedPassphraseServiceArg,
				encryptedContentServiceArg,
			)

			encodedContentArg := []byte("")

			actualReturn, actualErr := encryptedPayloadSvc.Deserialize(encodedContentArg)
			require.Nil(t, actualReturn)

			assert.Equal(t, errInvalidPayloadParts, actualErr)
		},
	)

	t.Run(
		"when 'encodedContent' contains only a header, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			b64ServiceArg := base64.NewBase64Service()

			headerServiceArg := header.NewHeaderService()
			encryptedPassphraseServiceArg := passphrase.NewEncryptedPassphraseService(
				b64ServiceArg,
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)
			encryptedContentServiceArg := content.NewLegacyEncryptedContentService(
				b64ServiceArg,
				aes.NewAesService(
					pkcs7.NewPkcs7Service(),
				),
			)

			encryptedPayloadSvc := NewEncryptedPayloadService(
				headerServiceArg,
				encryptedPassphraseServiceArg,
				encryptedContentServiceArg,
			)

			h := header.NewHeader()
			encodedContentArg := []byte(
				fmt.Sprintf("%s;%s", h.Name, h.Version),
			)

			actualReturn, actualErr := encryptedPayloadSvc.Deserialize(encodedContentArg)
			require.Nil(t, actualReturn)

			assert.Equal(t, errInvalidPayloadParts, actualErr)
		},
	)

	t.Run(
		"when 'encodedContent' contains only a header and encrypted passphrase, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			b64ServiceArg := base64.NewBase64Service()

			headerServiceArg := header.NewHeaderService()
			encryptedPassphraseService := passphrase.NewEncryptedPassphraseService(
				b64ServiceArg,
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)
			encryptedContentService := content.NewLegacyEncryptedContentService(
				b64ServiceArg,
				aes.NewAesService(
					pkcs7.NewPkcs7Service(),
				),
			)

			encryptedPayloadSvc := NewEncryptedPayloadService(
				headerServiceArg,
				encryptedPassphraseService,
				encryptedContentService,
			)

			serializedHeader, err := headerServiceArg.Serialize(
				header.NewHeader(),
			)
			require.Nil(t, err)

			encryptedPassphrase := passphrase.NewEncryptedPassphrase(
				[]byte("1a2b3c4d"),
			)

			serializedEncPassphrase, err := encryptedPassphraseService.Serialize(
				encryptedPassphrase,
			)
			require.Nil(t, err)

			encodedContent := fmt.Sprintf(
				"%s%s%s",
				serializedHeader,
				EncryptionPayloadSeparator,
				serializedEncPassphrase,
			)
			encodedContentArg := []byte(encodedContent)

			actualReturn, actualErr := encryptedPayloadSvc.Deserialize(encodedContentArg)
			require.Nil(t, actualReturn)

			assert.Equal(t, errInvalidPayloadParts, actualErr)
		},
	)

	t.Run(
		"when 'encodedContent' contains a header, encrypted passphrase, encrypted content, but header is empty, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			b64ServiceArg := base64.NewBase64Service()

			headerServiceArg := header.NewHeaderService()
			encryptedPassphraseService := passphrase.NewEncryptedPassphraseService(
				b64ServiceArg,
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)
			encryptedContentService := content.NewLegacyEncryptedContentService(
				b64ServiceArg,
				aes.NewAesService(
					pkcs7.NewPkcs7Service(),
				),
			)

			encryptedPayloadSvc := NewEncryptedPayloadService(
				headerServiceArg,
				encryptedPassphraseService,
				encryptedContentService,
			)

			encryptedPassphrase := passphrase.NewEncryptedPassphrase(
				[]byte("1a2b3c4d"),
			)

			serializedEncPassphrase, err := encryptedPassphraseService.Serialize(
				encryptedPassphrase,
			)
			require.Nil(t, err)

			serializedEncContent, err := encryptedContentService.Serialize(
				content.NewEncryptedContent(
					[]byte("1a2b3c"),
				),
			)
			require.Nil(t, err)

			encodedContent := fmt.Sprintf(
				"%s%s%s%s%s",
				// NOTE: Empty header,
				"",
				EncryptionPayloadSeparator,
				serializedEncPassphrase,
				EncryptionPayloadSeparator,
				serializedEncContent,
			)
			encodedContentArg := []byte(encodedContent)

			actualReturn, actualErr := encryptedPayloadSvc.Deserialize(encodedContentArg)
			require.Nil(t, actualReturn)

			assert.Equal(t, errEmptyHeader, actualErr)
		},
	)

	t.Run(
		"when 'encodedContent' contains a header, encrypted passphrase, encrypted content, but header does not contain all header parts, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			b64ServiceArg := base64.NewBase64Service()

			headerServiceArg := header.NewHeaderService()
			encryptedPassphraseService := passphrase.NewEncryptedPassphraseService(
				b64ServiceArg,
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)
			encryptedContentService := content.NewLegacyEncryptedContentService(
				b64ServiceArg,
				aes.NewAesService(
					pkcs7.NewPkcs7Service(),
				),
			)

			encryptedPayloadSvc := NewEncryptedPayloadService(
				headerServiceArg,
				encryptedPassphraseService,
				encryptedContentService,
			)

			encryptedPassphrase := passphrase.NewEncryptedPassphrase(
				[]byte("1a2b3c4d"),
			)

			serializedEncPassphrase, err := encryptedPassphraseService.Serialize(
				encryptedPassphrase,
			)
			require.Nil(t, err)

			serializedEncContent, err := encryptedContentService.Serialize(
				content.NewEncryptedContent(
					[]byte("1a2b3c"),
				),
			)
			require.Nil(t, err)

			partiallySerializedHeader := header.NewHeader().Name

			encodedContent := fmt.Sprintf(
				"%s%s%s%s%s",
				partiallySerializedHeader,
				EncryptionPayloadSeparator,
				serializedEncPassphrase,
				EncryptionPayloadSeparator,
				serializedEncContent,
			)
			encodedContentArg := []byte(encodedContent)

			actualReturn, actualErr := encryptedPayloadSvc.Deserialize(encodedContentArg)
			require.Nil(t, actualReturn)

			assert.Contains(t, actualErr.Error(), "failed to parse header")
		},
	)

	t.Run(
		"when 'encodedContent' contains a header, encrypted passphrase, encrypted content, but encrypted passphrase is blank, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			b64ServiceArg := base64.NewBase64Service()

			headerServiceArg := header.NewHeaderService()
			encryptedPassphraseService := passphrase.NewEncryptedPassphraseService(
				b64ServiceArg,
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)
			encryptedContentService := content.NewLegacyEncryptedContentService(
				b64ServiceArg,
				aes.NewAesService(
					pkcs7.NewPkcs7Service(),
				),
			)

			encryptedPayloadSvc := NewEncryptedPayloadService(
				headerServiceArg,
				encryptedPassphraseService,
				encryptedContentService,
			)

			serializedEncContent, err := encryptedContentService.Serialize(
				content.NewEncryptedContent(
					[]byte("1a2b3c"),
				),
			)
			require.Nil(t, err)

			serializedHeader, err := header.NewHeaderService().Serialize(
				header.NewHeader(),
			)
			require.Nil(t, err)

			encodedContent := fmt.Sprintf(
				"%s%s%s%s%s",
				serializedHeader,
				EncryptionPayloadSeparator,
				// NOTE: Empty encrypted passphrase
				"",
				EncryptionPayloadSeparator,
				serializedEncContent,
			)
			encodedContentArg := []byte(encodedContent)

			actualReturn, actualErr := encryptedPayloadSvc.Deserialize(encodedContentArg)
			require.Nil(t, actualReturn)

			assert.Equal(t, actualErr, errEmptyEncryptedPassphrase)
		},
	)

	t.Run(
		"when 'encodedContent' contains a header, encrypted passphrase, encrypted content, but encrypted passphrase fails base64 decoding, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			b64ServiceArg := base64.NewBase64Service()

			headerServiceArg := header.NewHeaderService()
			encryptedContentService := content.NewLegacyEncryptedContentService(
				b64ServiceArg,
				aes.NewAesService(
					pkcs7.NewPkcs7Service(),
				),
			)

			serializedEncContent, err := encryptedContentService.Serialize(
				content.NewEncryptedContent(
					[]byte("1a2b3c"),
				),
			)
			require.Nil(t, err)

			serializedHeader, err := header.NewHeaderService().Serialize(
				header.NewHeader(),
			)
			require.Nil(t, err)

			encPassphrase := passphrase.NewEncryptedPassphrase(
				[]byte("1a2b3c4d"),
			)

			badSerializedEncryptedPassphrase := fmt.Sprintf("%s", encPassphrase.Ciphertext)

			encodedContent := fmt.Sprintf(
				"%s%s%s%s%s",
				serializedHeader,
				EncryptionPayloadSeparator,
				badSerializedEncryptedPassphrase,
				EncryptionPayloadSeparator,
				serializedEncContent,
			)
			encodedContentArg := []byte(encodedContent)

			mockEncPassphraseSvc := &testPassphrase.MockEncryptedPassphraseService{}

			fakeError := errors.New("")

			mockEncPassphraseSvc.On(
				"Deserialize",
				[]byte(badSerializedEncryptedPassphrase),
			).Return(nil, fakeError)

			encryptedPayloadSvc := NewEncryptedPayloadService(
				headerServiceArg,
				mockEncPassphraseSvc,
				encryptedContentService,
			)
			actualReturn, actualErr := encryptedPayloadSvc.Deserialize(encodedContentArg)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to deserialize base64 encoded encrypted passphrase",
			)

			mockEncPassphraseSvc.AssertExpectations(t)
		},
	)

	t.Run(
		"when 'encodedContent' contains a header, encrypted passphrase, encrypted content, but encrypted content is blank, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			b64ServiceArg := base64.NewBase64Service()

			headerServiceArg := header.NewHeaderService()
			encryptedPassphraseService := passphrase.NewEncryptedPassphraseService(
				b64ServiceArg,
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)
			encryptedContentService := content.NewLegacyEncryptedContentService(
				b64ServiceArg,
				aes.NewAesService(
					pkcs7.NewPkcs7Service(),
				),
			)

			encryptedPayloadSvc := NewEncryptedPayloadService(
				headerServiceArg,
				encryptedPassphraseService,
				encryptedContentService,
			)

			serializedEncPassphrase, err := encryptedPassphraseService.Serialize(
				passphrase.NewEncryptedPassphrase(
					[]byte("1a2b3c"),
				),
			)
			require.Nil(t, err)

			serializedHeader, err := header.NewHeaderService().Serialize(
				header.NewHeader(),
			)
			require.Nil(t, err)

			encodedContent := fmt.Sprintf(
				"%s%s%s%s%s",
				serializedHeader,
				EncryptionPayloadSeparator,
				serializedEncPassphrase,
				EncryptionPayloadSeparator,
				// NOTE: Empty encrypted content
				"",
			)
			encodedContentArg := []byte(encodedContent)

			actualReturn, actualErr := encryptedPayloadSvc.Deserialize(encodedContentArg)
			require.Nil(t, actualReturn)

			assert.Equal(t, actualErr, errEmptyEncryptedContent)
		},
	)

	t.Run(
		"when 'encodedContent' contains a header, encrypted passphrase, encrypted content, but encrypted content base64 decoding fails, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			b64ServiceArg := base64.NewBase64Service()

			headerServiceArg := header.NewHeaderService()
			encryptedPassphraseService := passphrase.NewEncryptedPassphraseService(
				b64ServiceArg,
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)

			serializedEncPassphrase, err := encryptedPassphraseService.Serialize(
				passphrase.NewEncryptedPassphrase(
					[]byte("1a2b3c"),
				),
			)
			require.Nil(t, err)

			serializedHeader, err := header.NewHeaderService().Serialize(
				header.NewHeader(),
			)
			require.Nil(t, err)

			badSerializedEncryptedContent := "a1234"

			encodedContent := fmt.Sprintf(
				"%s%s%s%s%s",
				serializedHeader,
				EncryptionPayloadSeparator,
				serializedEncPassphrase,
				EncryptionPayloadSeparator,
				// NOTE: Empty encrypted content
				badSerializedEncryptedContent,
			)
			encodedContentArg := []byte(encodedContent)

			fakeError := errors.New("deserializeEncryptedContentError")
			mockEncContentSvc := &testContent.MockEncryptedContentService{}
			mockEncContentSvc.On(
				"Deserialize",
				[]byte(badSerializedEncryptedContent),
			).Return(nil, fakeError)

			encryptedPayloadSvc := NewEncryptedPayloadService(
				headerServiceArg,
				encryptedPassphraseService,
				mockEncContentSvc,
			)

			actualReturn, actualErr := encryptedPayloadSvc.Deserialize(encodedContentArg)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to deserialize base64 encoded encrypted content",
			)

			mockEncContentSvc.AssertExpectations(t)
		},
	)

	t.Run(
		"when 'encodedContent' contains a header, encrypted passphrase, encrypted content, it returns encrypted payload",
		func(t *testing.T) {
			t.Parallel()

			base64Svc := base64.NewBase64Service()
			svc := NewEncryptedPayloadService(
				header.NewHeaderService(),
				passphrase.NewEncryptedPassphraseService(
					base64Svc,
					rsa.NewRsaService(&os.RealOsExecutor{}),
				),
				content.NewLegacyEncryptedContentService(
					base64Svc,
					aes.NewAesService(
						pkcs7.NewPkcs7Service(),
					),
				),
			)

			encryptedPayload := NewEncryptedPayload(
				header.NewHeader(),
				passphrase.NewEncryptedPassphrase(
					[]byte("1a2b3c4d"),
				),
				content.NewEncryptedContent(
					[]byte("1a2b3c4d"),
				),
			)

			encodedArg, err := svc.Serialize(encryptedPayload)
			require.Nil(t, err)

			actualReturn, actualErr := svc.Deserialize(encodedArg)

			require.Nil(t, actualErr)

			assert.Equal(
				t,
				encryptedPayload.Header.Name,
				actualReturn.Header.Name,
			)

			assert.Equal(
				t,
				encryptedPayload.Header.Version,
				actualReturn.Header.Version,
			)

			assert.Equal(
				t,
				encryptedPayload.Header.Version,
				actualReturn.Header.Version,
			)

			assert.Equal(
				t,
				encryptedPayload.EncryptedPassphrase.Ciphertext,
				actualReturn.EncryptedPassphrase.Ciphertext,
			)

			assert.Equal(
				t,
				encryptedPayload.EncryptedContent.Ciphertext,
				actualReturn.EncryptedContent.Ciphertext,
			)
		},
	)
}

func TestEncryptedPayloadService_Encrypt(t *testing.T) {
	t.Run(
		"when encryption of 'payload's 'encryptedPassphrase' fails, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			b64Service := base64.NewBase64Service()
			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				b64Service,
				rsa.NewRsaService(
					ostest.NewFakeOsExecutor(t),
				),
			)

			fakeError := errors.New("encryptPassphraseError")
			passphrase, err := encPassphraseSvc.GeneratePassphrase(16)
			require.Nil(t, err)

			mockEncPassphraseSvc := &testPassphrase.MockEncryptedPassphraseService{}
			mockEncPassphraseSvc.Test(t)
			mockEncPassphraseSvc.On(
				"Encrypt",
				&privKey.PublicKey,
				passphrase,
			).Return(nil, fakeError)

			pkcs7Service := pkcs7.NewPkcs7Service()
			svc := NewEncryptedPayloadService(
				header.NewHeaderService(),
				mockEncPassphraseSvc,
				content.NewLegacyEncryptedContentService(
					b64Service,
					aes.NewAesService(pkcs7Service),
				),
			)

			payloadArg := NewPayload(
				header.NewHeader(),
				passphrase,
				content.NewContent(
					[]byte("samplecontent"),
				),
			)

			actualReturn, actualErr := svc.Encrypt(&privKey.PublicKey, payloadArg)
			require.Nil(t, actualReturn)

			assert.Contains(t, actualErr.Error(), "failed to encrypt encrypted passphrase")

			mockEncPassphraseSvc.AssertExpectations(t)
		},
	)

	t.Run(
		"when encryption of 'payload's 'encryptedContent' fails, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			b64Service := base64.NewBase64Service()
			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				b64Service,
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)
			passphrase, err := encPassphraseSvc.GeneratePassphrase(16)
			require.Nil(t, err)

			content := content.NewContent(
				[]byte("samplecontent"),
			)
			fakeError := errors.New("encryptContentError")

			mockEncContentSvc := &testContent.MockEncryptedContentService{}
			mockEncContentSvc.Test(t)
			mockEncContentSvc.On(
				"Encrypt",
				passphrase,
				content,
			).Return(nil, fakeError)

			svc := NewEncryptedPayloadService(
				header.NewHeaderService(),
				encPassphraseSvc,
				mockEncContentSvc,
			)

			payloadArg := NewPayload(
				header.NewHeader(),
				passphrase,
				content,
			)

			actualReturn, actualErr := svc.Encrypt(&privKey.PublicKey, payloadArg)
			require.Nil(t, actualReturn)

			assert.Contains(t, actualErr.Error(), "failed to encrypt encrypted content")

			mockEncContentSvc.AssertExpectations(t)
		},
	)

	t.Run(
		"when 'payload' is encrypted, it returns encrypted payload",
		func(t *testing.T) {
			t.Parallel()

			b64Svc := base64.NewBase64Service()
			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)
			passphrase, err := encPassphraseSvc.GeneratePassphrase(16)
			require.Nil(t, err)

			contentArg := content.NewContent(
				[]byte("mycontent"),
			)

			h := header.NewHeader()
			payload := NewPayload(h, passphrase, contentArg)

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			encContentSvc := content.NewLegacyEncryptedContentService(
				base64.NewBase64Service(),
				aes.NewAesService(
					pkcs7.NewPkcs7Service(),
				),
			)

			encPayloadSvc := NewEncryptedPayloadService(
				header.NewHeaderService(),
				encPassphraseSvc,
				encContentSvc,
			)

			actualReturn, actualErr := encPayloadSvc.Encrypt(&privKey.PublicKey, payload)
			require.Nil(t, actualErr)

			assert.Equal(t, h.Name, actualReturn.Header.Name)
			assert.Equal(t, h.Version, actualReturn.Header.Version)
			assert.NotContains(
				t,
				actualReturn.EncryptedPassphrase.Ciphertext,
				passphrase.Content,
			)

			assert.NotContains(
				t,
				actualReturn.EncryptedContent.Ciphertext,
				contentArg.Plaintext,
			)
		},
	)
}

func TestEncryptedPayloadService_Decrypt(t *testing.T) {
	t.Run(
		"when 'encryptedPayload's 'encryptedPassphrase' decryption fails, "+
			"it returns an error",
		func(t *testing.T) {
			t.Parallel()

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			b64Svc := base64.NewBase64Service()
			encryptedPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)

			wrongPrivKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			passphrase := &passphrase.Passphrase{
				Content: []byte("mysecretpassphrase"),
			}

			badEncryptedPassphrase, err := encryptedPassphraseSvc.Encrypt(
				&wrongPrivKey.PublicKey,
				passphrase,
			)
			require.Nil(t, err)

			encryptedPayloadArg := NewEncryptedPayload(
				header.NewHeader(),
				badEncryptedPassphrase,
				content.NewEncryptedContent(
					[]byte("a1b2c3"),
				),
			)

			svc := NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvc,
				content.NewLegacyEncryptedContentService(
					b64Svc,
					aes.NewAesService(
						pkcs7.NewPkcs7Service(),
					),
				),
			)

			actualReturn, actualErr := svc.Decrypt(privKey, encryptedPayloadArg)
			require.Nil(t, actualReturn)

			assert.Contains(t, actualErr.Error(), "failed to decrypt encrypted passphrase")
		},
	)

	t.Run(
		"when 'encryptedPayload's 'encryptedContent' decryption fails, "+
			"it returns an error",
		func(t *testing.T) {
			t.Parallel()

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			b64Svc := base64.NewBase64Service()
			encryptedPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)

			correctPassphrase, err := encryptedPassphraseSvc.GeneratePassphrase(16)
			require.Nil(t, err)

			encryptedPassphrase, err := encryptedPassphraseSvc.Encrypt(
				&privKey.PublicKey,
				correctPassphrase,
			)
			require.Nil(t, err)

			encryptedContentSvc := content.NewLegacyEncryptedContentService(
				b64Svc,
				aes.NewAesService(
					pkcs7.NewPkcs7Service(),
				),
			)

			// NOTE: Use a bad (different) passphrase
			// that is not the encrypted passphrase.
			badPassphrase, err := encryptedPassphraseSvc.GeneratePassphrase(16)
			require.Nil(t, err)

			content := content.NewContent([]byte("mycontent"))
			badEncryptedContent, err := encryptedContentSvc.Encrypt(
				badPassphrase,
				content,
			)
			require.Nil(t, err)

			encryptedPayloadArg := NewEncryptedPayload(
				header.NewHeader(),
				encryptedPassphrase,
				badEncryptedContent,
			)

			svc := NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvc,
				encryptedContentSvc,
			)

			actualReturn, actualErr := svc.Decrypt(privKey, encryptedPayloadArg)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"failed to decrypt encrypted content",
			)
		},
	)

	t.Run(
		"when 'encryptedPayload' is successfully decrypted, it returns payload",
		func(t *testing.T) {
			t.Parallel()

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			b64Svc := base64.NewBase64Service()

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				b64Svc,
				rsa.NewRsaService(&os.RealOsExecutor{}),
			)

			encContentSvc := content.NewLegacyEncryptedContentService(
				b64Svc,
				aes.NewAesService(
					pkcs7.NewPkcs7Service(),
				),
			)

			h := header.NewHeader()
			passphrase, err := encPassphraseSvc.GeneratePassphrase(16)
			require.Nil(t, err)

			encryptedPassphrase, err := encPassphraseSvc.Encrypt(&privKey.PublicKey, passphrase)
			require.Nil(t, err)

			content := content.NewContent(
				[]byte("mycontent!"),
			)
			encryptedContent, err := encContentSvc.Encrypt(passphrase, content)
			require.Nil(t, err)

			encryptedPayloadArg := NewEncryptedPayload(
				h,
				encryptedPassphrase,
				encryptedContent,
			)

			svc := NewEncryptedPayloadService(
				header.NewHeaderService(),
				encPassphraseSvc,
				encContentSvc,
			)

			actualReturn, actualErr := svc.Decrypt(privKey, encryptedPayloadArg)
			require.Nil(t, actualErr)

			assert.Equal(t, h.Name, actualReturn.Header.Name)
			assert.Equal(t, h.Version, actualReturn.Header.Version)
			assert.Equal(t, passphrase.Content, actualReturn.Passphrase.Content)
			assert.Equal(t, content.Plaintext, actualReturn.Content.Plaintext)
		},
	)
}
