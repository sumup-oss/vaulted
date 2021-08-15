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

import "github.com/palantir/stacktrace"

type DecryptionService struct {
	passphraseDecrypter passphraseDecrypter
	contentDecrypter    contentDecrypter
}

func NewDecryptionService(passphraseDecrypter passphraseDecrypter, contentDecrypter contentDecrypter) *DecryptionService {
	return &DecryptionService{
		passphraseDecrypter: passphraseDecrypter,
		contentDecrypter:    contentDecrypter,
	}
}

func (s *DecryptionService) Decrypt(encryptedPayload *EncryptedPayload) (*Payload, error) {
	passphraseInstance, err := s.passphraseDecrypter.Decrypt(encryptedPayload.EncryptedPassphrase)
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed to decrypt encrypted passphrase")
	}

	contentInstance, err := s.contentDecrypter.Decrypt(passphraseInstance, encryptedPayload.EncryptedContent)
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed to decrypt content with decrypted passphrase")
	}

	payloadInstance := NewPayload(
		encryptedPayload.Header,
		passphraseInstance,
		contentInstance,
	)

	return payloadInstance, nil
}
