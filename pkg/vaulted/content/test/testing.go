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
	"github.com/stretchr/testify/mock"

	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
)

type MockEncryptedContentService struct {
	mock.Mock
}

func (m *MockEncryptedContentService) Decrypt(
	passphrase *passphrase.Passphrase,
	encryptedContent *content.EncryptedContent,
) (*content.Content, error) {
	args := m.Called(passphrase, encryptedContent)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*content.Content), err
}

func (m *MockEncryptedContentService) Deserialize(encoded []byte) (*content.EncryptedContent, error) {
	args := m.Called(encoded)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*content.EncryptedContent), err
}

func (m *MockEncryptedContentService) Encrypt(
	passphrase *passphrase.Passphrase,
	contentArg *content.Content,
) (*content.EncryptedContent, error) {
	args := m.Called(passphrase, contentArg)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*content.EncryptedContent), err
}

func (m *MockEncryptedContentService) Serialize(encryptedContent *content.EncryptedContent) ([]byte, error) {
	args := m.Called(encryptedContent)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.([]byte), err
}
