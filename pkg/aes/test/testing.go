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
)

type MockAesService struct {
	mock.Mock
}

func (m *MockAesService) EncryptCBC(key []byte, plaintext []byte) ([]byte, error) {
	args := m.Called(key, plaintext)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.([]byte), err
}

func (m *MockAesService) DecryptCBC(key []byte, plaintext []byte) ([]byte, error) {
	args := m.Called(key, plaintext)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.([]byte), err
}

func (m *MockAesService) EncryptGCM(key []byte, plaintext []byte) ([]byte, error) {
	args := m.Called(key, plaintext)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.([]byte), err
}

func (m *MockAesService) DecryptGCM(key []byte, plaintext []byte) ([]byte, error) {
	args := m.Called(key, plaintext)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.([]byte), err
}
