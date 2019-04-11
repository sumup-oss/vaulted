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

package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/palantir/stacktrace"
)

const (
	// NOTE: Due to Golang's `aes.NewCipher`
	// implementation, anything other than `16bytes` (AES-128) will not work.
	// AES-192 and AES-256 are not possible using CBC.
	aesCBCblockSize = 16
	// NOTE: This is AES-256 block size
	aesGCMblockSize = 32
	// NOTE: Standard AES-256 GCM nonce size
	aesGCMNonceSize = 12
)

var (
	errInvalidBlockSize   = errors.New("value is not a multiple of the block size")
	errTooShortCiphertext = errors.New(
		"invalid ciphertext. its length is shorter than AES blocksize",
	)
	errInvalidCBCKeySize = fmt.Errorf(
		"invalid AES key size for CBC encryption. it must be exactly %d",
		aesCBCblockSize,
	)
	errInvalidGCMKeySize = fmt.Errorf(
		"invalid AES key size for GCM encryption. it must be exactly %d",
		aesGCMblockSize,
	)
	errInvalidEmptyPayload = errors.New("invalid empty payload to encrypt or decrypt")
)

type Service struct {
	pkcs7Service pkcs7Service
}

func NewAesService(pkcs7Service pkcs7Service) *Service {
	return &Service{
		pkcs7Service: pkcs7Service,
	}
}

func (s *Service) EncryptCBC(key []byte, plaintext []byte) ([]byte, error) {
	paddedPlaintext, err := s.pkcs7Service.Pad(plaintext, aesCBCblockSize)
	if err != nil {
		return nil, err
	}

	if len(paddedPlaintext)%aesCBCblockSize != 0 {
		return nil, errInvalidBlockSize
	}

	if len(key) != aesCBCblockSize {
		return nil, errInvalidCBCKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to create AES cipher")
	}

	ciphertext := make([]byte, aesCBCblockSize+len(paddedPlaintext))

	iv := ciphertext[:aesCBCblockSize]

	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aesCBCblockSize:], paddedPlaintext)

	return ciphertext, nil
}

func (s *Service) DecryptCBC(key []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != aesCBCblockSize {
		return nil, errInvalidCBCKeySize
	}

	if len(ciphertext) < aesCBCblockSize {
		return nil, errTooShortCiphertext
	}

	pad := ciphertext[aesCBCblockSize:]

	if len(pad)%aesCBCblockSize != 0 {
		return nil, errInvalidBlockSize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to create AES cipher")
	}

	iv := ciphertext[:aesCBCblockSize]

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(pad, pad)

	plaintext, err := s.pkcs7Service.Unpad(pad, aesCBCblockSize)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (s *Service) EncryptGCM(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != aesGCMblockSize {
		return nil, errInvalidGCMKeySize
	}

	if len(plaintext) < 1 {
		return nil, errInvalidEmptyPayload
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to create AES cipher")
	}

	nonce := make([]byte, aesGCMNonceSize)

	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to create AES-GCM cipher")
	}

	ciphertext := mode.Seal(nil, nonce, plaintext, nil)

	var nonceAndCipher []byte
	nonceAndCipher = append(nonceAndCipher, nonce...)
	nonceAndCipher = append(nonceAndCipher, ciphertext...)

	return nonceAndCipher, nil
}

func (s *Service) DecryptGCM(key []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != aesGCMblockSize {
		return nil, errInvalidGCMKeySize
	}

	if len(ciphertext) < 1 {
		return nil, errInvalidEmptyPayload
	}

	nonce := ciphertext[:aesGCMNonceSize]
	ciphertextWithoutNonce := ciphertext[aesGCMNonceSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to create AES cipher")
	}

	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to create AES-GCM cipher")
	}

	plaintext, err := mode.Open(nil, nonce, ciphertextWithoutNonce, nil)
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to decrypt AES-GCM ciphertext")
	}

	return plaintext, nil
}
