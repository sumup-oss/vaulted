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
	stdRsa "crypto/rsa"

	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
)

type headerService interface {
	Serialize(header *header.Header) ([]byte, error)
	Deserialize(content string) (*header.Header, error)
}

type encryptedPassphraseService interface {
	Serialize(encryptedPassphrase *passphrase.EncryptedPassphrase) ([]byte, error)
	Deserialize(encoded []byte) (*passphrase.EncryptedPassphrase, error)
	Encrypt(
		publicKey *stdRsa.PublicKey,
		passphrase *passphrase.Passphrase,
	) (*passphrase.EncryptedPassphrase, error)
	Decrypt(
		privateKey *stdRsa.PrivateKey,
		encryptedPassphrase *passphrase.EncryptedPassphrase,
	) (*passphrase.Passphrase, error)
}

type encryptedContentService interface {
	Serialize(encryptedContent *content.EncryptedContent) ([]byte, error)
	Deserialize(encoded []byte) (*content.EncryptedContent, error)
	Encrypt(
		passphrase *passphrase.Passphrase,
		content *content.Content,
	) (*content.EncryptedContent, error)
	Decrypt(
		passphrase *passphrase.Passphrase,
		encryptedContent *content.EncryptedContent,
	) (*content.Content, error)
}
