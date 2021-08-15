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
	"crypto/rsa"

	"github.com/palantir/stacktrace"
)

type EncRsaPKCS1v15Service struct {
	rsaSvc    rsaService
	publicKey *rsa.PublicKey
}

func NewEncryptionRsaPKCS1v15Service(rsaSvc rsaService, publicKey *rsa.PublicKey) *EncRsaPKCS1v15Service {
	return &EncRsaPKCS1v15Service{
		rsaSvc:    rsaSvc,
		publicKey: publicKey,
	}
}

func (s *EncRsaPKCS1v15Service) Encrypt(passphrase *Passphrase) (*EncryptedPassphrase, error) {
	ciphertext, err := s.rsaSvc.EncryptPKCS1v15(
		rand.Reader,
		s.publicKey,
		passphrase.Content,
	)
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed to encrypt passphrase using PKCS#1v15")
	}

	return NewEncryptedPassphrase(ciphertext), nil
}
