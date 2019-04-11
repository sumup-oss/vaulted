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

type MockPkcs7Service struct {
	mock.Mock
}

func (m *MockPkcs7Service) Pad(bytesValue []byte, blockSize int) ([]byte, error) {
	args := m.Called(bytesValue, blockSize)
	returnValue := args.Get(0)

	// NOTE: Workaround lack of get bytes without type-assertion method.
	if returnValue == nil {
		return nil, args.Error(1)
	}

	return returnValue.([]byte), args.Error(1)
}

func (m *MockPkcs7Service) Unpad(bytesValue []byte, blockSize int) ([]byte, error) {
	args := m.Called(bytesValue, blockSize)
	returnValue := args.Get(0)

	// NOTE: Workaround lack of get bytes without type-assertion method.
	if returnValue == nil {
		return nil, args.Error(1)
	}

	return returnValue.([]byte), args.Error(1)
}
