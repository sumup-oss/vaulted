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
	"bytes"
	"errors"
)

var (
	errZeroLengthValue        = errors.New("invalid bytes value. zero-length value")
	errLesserThanOneBlockSize = errors.New(
		"invalid blocksize. it must be greater than or equal to 1",
	)
	errInconsistentPadding            = errors.New("invalid padding. inconsistent or non-PKCS#7 padding")
	errBytesValueNotMatchingBlockSize = errors.New(
		"invalid bytes value length. not padded in blocksize via PKCS#7",
	)
)

type Service struct{}

func NewPkcs7Service() *Service {
	return &Service{}
}

// Pad rights-pad the given `bytesValue` up to 1 or N bytes.
// The `blockSize` is between 1 to N int.
// The padded `bytesValue` length is >=1 (gte) times `blockSize`.
func (p *Service) Pad(bytesValue []byte, blockSize int) ([]byte, error) {
	if len(bytesValue) == 0 {
		return nil, errZeroLengthValue
	}

	if blockSize <= 0 {
		return nil, errLesserThanOneBlockSize
	}

	padSize := blockSize - (len(bytesValue) % blockSize)
	if padSize == 0 {
		padSize = blockSize
	}

	pad := bytes.Repeat(
		[]byte{
			byte(padSize),
		},
		padSize,
	)

	return append(bytesValue, pad...), nil
}

func (p *Service) Unpad(bytesValue []byte, blockSize int) ([]byte, error) {
	if len(bytesValue) == 0 {
		return nil, errZeroLengthValue
	}

	if blockSize <= 0 {
		return nil, errLesserThanOneBlockSize
	}

	if len(bytesValue)%blockSize != 0 {
		return nil, errBytesValueNotMatchingBlockSize
	}

	lastByte := bytesValue[len(bytesValue)-1]
	padSize := int(lastByte)

	valueLengthBeforePad := len(bytesValue) - padSize
	if valueLengthBeforePad < 0 {
		return nil, errInconsistentPadding
	}

	pad := bytesValue[valueLengthBeforePad:]

	for _, padByte := range pad {
		if padByte != byte(padSize) {
			return nil, errInconsistentPadding
		}
	}

	return bytesValue[:len(bytesValue)-padSize], nil
}
