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
	stdRsa "crypto/rsa"
	"io"

	"github.com/stretchr/testify/mock"
)

type MockRsaService struct {
	mock.Mock
}

func (m *MockRsaService) ReadPublicKeyFromPath(publicKeyPath string) (*stdRsa.PublicKey, error) {
	args := m.Called(publicKeyPath)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*stdRsa.PublicKey), err
}

func (m *MockRsaService) ReadPrivateKeyFromPath(privateKeyPath string) (*stdRsa.PrivateKey, error) {
	args := m.Called(privateKeyPath)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*stdRsa.PrivateKey), err
}

func (m *MockRsaService) EncryptPKCS1v15(rand io.Reader, pub *stdRsa.PublicKey, msg []byte) ([]byte, error) {
	args := m.Called(rand, pub, msg)

	returnValue := args.Get(0)

	// NOTE: Workaround lack of get bytes without type-assertion method.
	if returnValue == nil {
		return nil, args.Error(1)
	}

	return returnValue.([]byte), args.Error(1)
}

func (m *MockRsaService) DecryptPKCS1v15(rand io.Reader, priv *stdRsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	args := m.Called(rand, priv, ciphertext)

	returnValue := args.Get(0)

	// NOTE: Workaround lack of get bytes without type-assertion method.
	if returnValue == nil {
		return nil, args.Error(1)
	}

	return returnValue.([]byte), args.Error(1)
}
