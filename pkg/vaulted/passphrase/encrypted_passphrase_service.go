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

package passphrase

import (
	"crypto/rand"
	stdRsa "crypto/rsa"

	"github.com/palantir/stacktrace"
)

type EncryptedPassphraseService struct {
	base64Service base64Service
	rsaService    rsaService
}

func NewEncryptedPassphraseService(
	base64Service base64Service,
	rsaService rsaService,
) *EncryptedPassphraseService {
	return &EncryptedPassphraseService{
		base64Service: base64Service,
		rsaService:    rsaService,
	}
}

func (s *EncryptedPassphraseService) Serialize(encryptedPassphrase *EncryptedPassphrase) ([]byte, error) {
	return s.base64Service.Serialize(encryptedPassphrase.Ciphertext)
}

func (s *EncryptedPassphraseService) Deserialize(encoded []byte) (*EncryptedPassphrase, error) {
	decoded, err := s.base64Service.Deserialize(encoded)
	if err != nil {
		return nil, stacktrace.Propagate(
			err,
			"failed to deserialize base64 encoded encrypted passphrase",
		)
	}

	encryptedPassphrase := NewEncryptedPassphrase(decoded)
	return encryptedPassphrase, nil
}

func (s *EncryptedPassphraseService) Encrypt(
	publicKey *stdRsa.PublicKey,
	passphrase *Passphrase,
) (*EncryptedPassphrase, error) {
	ciphertext, err := s.rsaService.EncryptPKCS1v15(
		rand.Reader,
		publicKey,
		passphrase.Content,
	)
	if err != nil {
		return nil, err
	}

	return NewEncryptedPassphrase(
		ciphertext,
	), nil
}

func (s *EncryptedPassphraseService) Decrypt(
	privateKey *stdRsa.PrivateKey,
	encryptedPassphrase *EncryptedPassphrase,
) (*Passphrase, error) {
	plaintext, err := s.rsaService.DecryptPKCS1v15(
		rand.Reader,
		privateKey,
		encryptedPassphrase.Ciphertext,
	)
	if err != nil {
		return nil, err
	}

	return newPassphrase(plaintext), nil
}

func (s *EncryptedPassphraseService) GeneratePassphrase(length int) (*Passphrase, error) {
	b := make([]byte, length)
	_, err := randRead(b)
	if err != nil {
		return nil, err
	}

	return newPassphrase(b), nil
}
