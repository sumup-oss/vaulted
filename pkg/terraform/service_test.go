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
	stdRsa "crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
)

type mockEncryptedPassphraseService struct {
	mock.Mock
}

func (m *mockEncryptedPassphraseService) GeneratePassphrase(length int) (*passphrase.Passphrase, error) {
	args := m.Called(length)
	returnValue := args.Get(0)
	err := args.Error(1)
	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*passphrase.Passphrase), err
}

func (m *mockEncryptedPassphraseService) Serialize(
	encryptedPassphrase *passphrase.EncryptedPassphrase,
) ([]byte, error) {
	args := m.Called(encryptedPassphrase)
	returnValue := args.Get(0)

	// NOTE: Workaround lack of get bytes without type-assertion method.
	if returnValue == nil {
		return nil, args.Error(1)
	}

	return returnValue.([]byte), args.Error(1)
}

func (m *mockEncryptedPassphraseService) Deserialize(
	encoded []byte,
) (*passphrase.EncryptedPassphrase, error) {
	args := m.Called(encoded)
	returnValue := args.Get(0)

	if returnValue == nil {
		return nil, args.Error(1)
	}

	return returnValue.(*passphrase.EncryptedPassphrase), args.Error(1)
}

func (m *mockEncryptedPassphraseService) Encrypt(
	publicKey *stdRsa.PublicKey,
	passphraseArg *passphrase.Passphrase,
) (*passphrase.EncryptedPassphrase, error) {
	args := m.Called(publicKey, passphraseArg)
	returnValue := args.Get(0)

	if returnValue == nil {
		return nil, args.Error(1)
	}

	return returnValue.(*passphrase.EncryptedPassphrase), args.Error(1)
}

func (m *mockEncryptedPassphraseService) Decrypt(
	privateKey *stdRsa.PrivateKey,
	encryptedPassphrase *passphrase.EncryptedPassphrase,
) (*passphrase.Passphrase, error) {
	args := m.Called(privateKey, encryptedPassphrase)
	returnValue := args.Get(0)

	if returnValue == nil {
		return nil, args.Error(1)
	}

	return returnValue.(*passphrase.Passphrase), args.Error(1)
}

type mockEncryptedContentService struct {
	mock.Mock
}

func (m *mockEncryptedContentService) Serialize(
	encryptedContent *content.EncryptedContent,
) ([]byte, error) {
	args := m.Called(encryptedContent)
	returnValue := args.Get(0)

	// NOTE: Workaround lack of get bytes without type-assertion method.
	if returnValue == nil {
		return nil, args.Error(1)
	}

	return returnValue.([]byte), args.Error(1)
}

func (m *mockEncryptedContentService) Deserialize(
	encoded []byte,
) (*content.EncryptedContent, error) {
	args := m.Called(encoded)
	returnValue := args.Get(0)

	// NOTE: Workaround lack of get bytes without type-assertion method.
	if returnValue == nil {
		return nil, args.Error(1)
	}

	return returnValue.(*content.EncryptedContent), args.Error(1)
}

func (m *mockEncryptedContentService) Encrypt(
	passphrase *passphrase.Passphrase,
	contentArg *content.Content,
) (*content.EncryptedContent, error) {
	args := m.Called(passphrase, contentArg)
	returnValue := args.Get(0)

	// NOTE: Workaround lack of get bytes without type-assertion method.
	if returnValue == nil {
		return nil, args.Error(1)
	}

	return returnValue.(*content.EncryptedContent), args.Error(1)
}

func (m *mockEncryptedContentService) Decrypt(
	passphrase *passphrase.Passphrase,
	encryptedContent *content.EncryptedContent,
) (*content.Content, error) {
	args := m.Called(passphrase, encryptedContent)
	returnValue := args.Get(0)

	// NOTE: Workaround lack of get bytes without type-assertion method.
	if returnValue == nil {
		return nil, args.Error(1)
	}

	return returnValue.(*content.Content), args.Error(1)
}

func TestNewTerraformService(t *testing.T) {
	t.Run(
		"it creates a terraform Service",
		func(t *testing.T) {
			t.Parallel()

			actual := NewTerraformService()

			assert.IsType(t, actual, &Service{})
		},
	)
}
