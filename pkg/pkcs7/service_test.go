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

package pkcs7

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPkcs7_Constants(t *testing.T) {
	t.Parallel()

	assert.Equal(
		t,
		"invalid bytes value. zero-length value",
		errZeroLengthValue.Error(),
	)
	assert.Equal(
		t,
		"invalid blocksize. it must be greater than or equal to 1",
		errLesserThanOneBlockSize.Error(),
	)
	assert.Equal(
		t,
		"invalid padding. inconsistent or non-PKCS#7 padding",
		errInconsistentPadding.Error(),
	)
	assert.Equal(
		t,
		"invalid bytes value length. not padded in blocksize via PKCS#7",
		errBytesValueNotMatchingBlockSize.Error(),
	)
}

func TestNewPkcs7Service(t *testing.T) {
	t.Run(
		"returns new PKCS7 service",
		func(t *testing.T) {
			t.Parallel()

			actual := NewPkcs7Service()
			require.NotNil(t, actual)
			assert.IsType(t, actual, &Service{})
		},
	)
}

func TestService_Pad(t *testing.T) {
	t.Run(
		"when 'bytesValue' is zero-length, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			//noinspection GoPreferNilSlice
			bytesValueArg := []byte{}
			blockSizeArg := 12

			svc := NewPkcs7Service()
			actualReturn, actualErr := svc.Pad(bytesValueArg, blockSizeArg)

			require.Nil(t, actualReturn)

			assert.Equal(t, actualErr, errZeroLengthValue)
		},
	)

	t.Run(
		"when 'bytesValue' is not zero-length and 'blockSize' is 0, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			bytesValueArg := []byte{1, 2, 3, 4}

			blockSizeArg := 0

			svc := NewPkcs7Service()
			actualReturn, actualErr := svc.Pad(bytesValueArg, blockSizeArg)

			require.Nil(t, actualReturn)

			assert.Equal(t, actualErr, errLesserThanOneBlockSize)
		},
	)

	t.Run(
		"when 'bytesValue' is not zero-length and 'blockSize' is negative number, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			bytesValueArg := []byte{1, 2, 3, 4}

			blockSizeArg := -10

			svc := NewPkcs7Service()
			actualReturn, actualErr := svc.Pad(bytesValueArg, blockSizeArg)

			require.Nil(t, actualReturn)

			assert.Equal(t, actualErr, errLesserThanOneBlockSize)
		},
	)

	t.Run(
		"when 'bytesValue' and 'blockSize' are positive and equal in size, it returns value padded to 2x the size",
		func(t *testing.T) {
			t.Parallel()

			bytesValueArg := []byte{1, 2, 3, 4, 5, 6, 7, 8}

			assert.Equal(t, len(bytesValueArg), 8)

			blockSizeArg := 8

			svc := NewPkcs7Service()
			actualReturn, actualErr := svc.Pad(bytesValueArg, blockSizeArg)

			require.NoError(t, actualErr)
			assert.Equal(t, len(actualReturn), blockSizeArg*2)
			assert.Equal(t, actualReturn[:8], bytesValueArg)
		},
	)

	t.Run(
		"when 'bytesValue' and 'blockSize' are positive and 'bytesValue' is longer, it returns value padded up to 'bytesValue + blockSize' length",
		func(t *testing.T) {
			t.Parallel()

			bytesValueArg := []byte{1, 2, 3, 4, 5, 6, 7, 8}

			assert.Equal(t, len(bytesValueArg), 8)

			blockSizeArg := 4 + len(bytesValueArg)

			svc := NewPkcs7Service()
			actualReturn, actualErr := svc.Pad(bytesValueArg, blockSizeArg)

			require.NoError(t, actualErr)
			assert.Equal(t, len(actualReturn), blockSizeArg)
			assert.Equal(t, actualReturn[:8], bytesValueArg)
		},
	)

	t.Run(
		"when 'bytesValue' and 'blockSize' are positive and 'bytesValue' is shorter, it returns value padded up to 'blockSize' length",
		func(t *testing.T) {
			t.Parallel()

			bytesValueArg := []byte{1, 2, 3, 4}

			assert.Equal(t, len(bytesValueArg), 4)

			blockSizeArg := 8

			svc := NewPkcs7Service()
			actualReturn, actualErr := svc.Pad(bytesValueArg, blockSizeArg)

			require.NoError(t, actualErr)
			assert.Equal(t, len(actualReturn), blockSizeArg)
			assert.Equal(t, actualReturn[:4], bytesValueArg)
		},
	)
}

func TestService_Unpad(t *testing.T) {
	t.Run(
		"with nil 'bytesValue', it returns error",
		func(t *testing.T) {
			t.Parallel()

			var bytesValueArg []byte
			bytesValueArg = nil
			blockSizeArg := 1

			svc := NewPkcs7Service()
			actualReturn, actualErr := svc.Unpad(bytesValueArg, blockSizeArg)
			require.Nil(t, actualReturn)

			assert.Equal(t, errZeroLengthValue, actualErr)
		},
	)

	t.Run(
		"with nil 'bytesValue', it returns error",
		func(t *testing.T) {
			t.Parallel()

			var bytesValueArg []byte
			bytesValueArg = nil
			blockSizeArg := 1

			svc := NewPkcs7Service()
			actualReturn, actualErr := svc.Unpad(bytesValueArg, blockSizeArg)
			require.Nil(t, actualReturn)

			assert.Equal(t, errZeroLengthValue, actualErr)
		},
	)

	t.Run(
		"with zero-length 'bytesValue', it returns error",
		func(t *testing.T) {
			t.Parallel()

			//noinspection GoPreferNilSlice
			bytesValueArg := []byte{}
			blockSizeArg := 1

			svc := NewPkcs7Service()
			actualReturn, actualErr := svc.Unpad(bytesValueArg, blockSizeArg)
			require.Nil(t, actualReturn)

			assert.Equal(t, errZeroLengthValue, actualErr)
		},
	)

	t.Run(
		"when 'bytesValue' is not zero-length and 'blockSize' is negative number, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			bytesValueArg := []byte{1, 2, 3, 4}

			blockSizeArg := -10

			svc := NewPkcs7Service()
			actualReturn, actualErr := svc.Unpad(bytesValueArg, blockSizeArg)

			require.Nil(t, actualReturn)

			assert.Equal(t, actualErr, errLesserThanOneBlockSize)
		},
	)

	t.Run(
		"when 'bytesValue' is not up to N times 'blockSize' length, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			bytesValueArg := []byte{1, 2, 3, 4}

			blockSizeArg := 5

			svc := NewPkcs7Service()
			actualReturn, actualErr := svc.Unpad(bytesValueArg, blockSizeArg)

			require.Nil(t, actualReturn)

			assert.Equal(t, actualErr, errBytesValueNotMatchingBlockSize)
		},
	)

	t.Run(
		"when 'bytesValue' is inconsistently padded with various length and up to 'blockSize', it returns an error",
		func(t *testing.T) {
			t.Parallel()

			bytesValueArg := []byte("hello\x01\x02")

			blockSizeArg := 4

			svc := NewPkcs7Service()
			actualReturn, actualErr := svc.Unpad(bytesValueArg, blockSizeArg)

			require.Nil(t, actualReturn)

			assert.Equal(t, actualErr, errBytesValueNotMatchingBlockSize)
		},
	)

	t.Run(
		"when 'bytesValue' length is equal to length of 'blockSize', it returns an error",
		func(t *testing.T) {
			t.Parallel()

			bytesValueArg := []byte{0, 1, 2, 3}

			blockSizeArg := 4

			svc := NewPkcs7Service()
			actualReturn, actualErr := svc.Unpad(bytesValueArg, blockSizeArg)

			require.Nil(t, actualReturn)

			assert.Equal(t, errInconsistentPadding, actualErr)
		},
	)

	t.Run(
		"when 'bytesValue' is padded up to 'blockSize' length, but padding bytes are differentiating, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			blockSizeArg := 5
			// NOTE: 2 padded characters due to the fact that the content is 3 length,
			// but block size is 5.
			// `0x05` is the irregular character at fault.
			bytesValueArg := []byte{'a', 'b', 'c', 0x2, 0x5}

			svc := NewPkcs7Service()

			actualReturn, actualErr := svc.Unpad(bytesValueArg, blockSizeArg)

			require.Nil(t, actualReturn)

			assert.Equal(t, errInconsistentPadding, actualErr)
		},
	)

	t.Run(
		"when 'bytesValue' is padded up to 'blockSize' length and padding bytes are the same, it returns unpadded value and no error",
		func(t *testing.T) {
			t.Parallel()

			blockSizeArg := 5
			// NOTE: 2 padded characters due to the fact that the content is 3 length,
			// but block size is 5.
			bytesValueArg := []byte{'a', 'b', 'c', 0x2, 0x2}

			svc := NewPkcs7Service()

			actualReturn, actualErr := svc.Unpad(bytesValueArg, blockSizeArg)

			require.Nil(t, actualErr)

			assert.Equal(t, "abc", string(actualReturn))
		},
	)
}
