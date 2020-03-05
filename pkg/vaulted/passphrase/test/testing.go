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

package test

import (
	"crypto/rsa"

	"github.com/stretchr/testify/mock"

	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
)

type MockEncryptedPassphraseService struct {
	mock.Mock
}

func (m *MockEncryptedPassphraseService) Decrypt(
	privateKey *rsa.PrivateKey,
	encryptedPassphrase *passphrase.EncryptedPassphrase,
) (*passphrase.Passphrase, error) {
	args := m.Called(privateKey, encryptedPassphrase)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*passphrase.Passphrase), err
}

func (m *MockEncryptedPassphraseService) Deserialize(encoded []byte) (*passphrase.EncryptedPassphrase, error) {
	args := m.Called(encoded)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*passphrase.EncryptedPassphrase), err
}

func (m *MockEncryptedPassphraseService) Encrypt(
	publicKey *rsa.PublicKey,
	passphraseArg *passphrase.Passphrase,
) (*passphrase.EncryptedPassphrase, error) {
	args := m.Called(publicKey, passphraseArg)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*passphrase.EncryptedPassphrase), err
}

func (m *MockEncryptedPassphraseService) GeneratePassphrase(length int) (*passphrase.Passphrase, error) {
	args := m.Called(length)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*passphrase.Passphrase), err
}

func (m *MockEncryptedPassphraseService) Serialize(
	encryptedPassphrase *passphrase.EncryptedPassphrase,
) ([]byte, error) {
	args := m.Called(encryptedPassphrase)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.([]byte), err
}
