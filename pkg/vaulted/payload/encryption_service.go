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

package payload

import (
	"github.com/palantir/stacktrace"
)

type EncryptionService struct {
	passphraseEncrypter passphraseEncrypter
	contentEncrypter    contentEncrypter
}

func NewEncryptionService(passphraseEncrypter passphraseEncrypter, contentEncrypter contentEncrypter) *EncryptionService {
	return &EncryptionService{
		passphraseEncrypter: passphraseEncrypter,
		contentEncrypter:    contentEncrypter,
	}
}

func (s *EncryptionService) Encrypt(payload *Payload) (*EncryptedPayload, error) {
	encryptedContent, err := s.contentEncrypter.Encrypt(payload.Passphrase, payload.Content)
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed to encrypt content using generated passphrase")
	}

	encryptedPassphrase, err := s.passphraseEncrypter.Encrypt(payload.Passphrase)
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed to encrypt passphrase")
	}

	encryptedPayload := NewEncryptedPayload(
		payload.Header,
		encryptedPassphrase,
		encryptedContent,
	)

	return encryptedPayload, nil
}
