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

package base64

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewBase64Service(t *testing.T) {
	t.Run(
		"it creates a new base64 Service",
		func(t *testing.T) {
			t.Parallel()

			actual := NewBase64Service()

			assert.IsType(t, actual, &Service{})
		},
	)
}

func TestService_Serialize(t *testing.T) {
	t.Run(
		"when 'rawArg' is specified, it returns it serialized to base64",
		func(t *testing.T) {
			rawArg := []byte("foobar")

			svc := NewBase64Service()

			actualReturn, actualErr := svc.Serialize(rawArg)

			require.Nil(t, actualErr)

			expectedReturn := []byte("Zm9vYmFy")
			assert.Equal(t, expectedReturn, actualReturn)
		},
	)
}

func TestService_Deserialize(t *testing.T) {
	t.Run(
		"when non-blank 'encoded' is specified, it returns deserialized 'encoded' from base64",
		func(t *testing.T) {
			encodedArg := []byte("Zm9vYmFy")

			svc := NewBase64Service()

			actualReturn, actualErr := svc.Deserialize(encodedArg)

			require.Nil(t, actualErr)

			expectedReturn := []byte("foobar")
			assert.Equal(t, expectedReturn, actualReturn)
		},
	)
}
