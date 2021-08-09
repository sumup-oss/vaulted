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

package external_interfaces

import (
	stdRsa "crypto/rsa"
	"hash"
	"io"

	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

type HclService interface {
	hcl.Parser
}

type Base64Service interface {
	Serialize(raw []byte) ([]byte, error)
	Deserialize(encoded []byte) ([]byte, error)
}

type EncryptedPassphraseService interface {
	GeneratePassphrase(length int) (*passphrase.Passphrase, error)
	Serialize(encryptedPassphrase *passphrase.EncryptedPassphrase) ([]byte, error)
	Deserialize(encoded []byte) (*passphrase.EncryptedPassphrase, error)
	Encrypt(
		useOAEP bool,
		publicKey *stdRsa.PublicKey,
		passphrase *passphrase.Passphrase,
	) (*passphrase.EncryptedPassphrase, error)
	Decrypt(
		kmsKeyID string,
		privateKey *stdRsa.PrivateKey,
		encryptedPassphrase *passphrase.EncryptedPassphrase,
	) (*passphrase.Passphrase, error)
}

type EncryptedPayloadService interface {
	Encrypt(useOAEP bool, publicKey *stdRsa.PublicKey, payload *payload.Payload) (*payload.EncryptedPayload, error)
	Decrypt(kmsKeyID string, privateKey *stdRsa.PrivateKey, encryptedPayload *payload.EncryptedPayload) (*payload.Payload, error)
	Serialize(encryptedPayload *payload.EncryptedPayload) ([]byte, error)
	Deserialize(encodedContent []byte) (*payload.EncryptedPayload, error)
}

type EncryptedContentService interface {
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

type RsaService interface {
	ReadPublicKeyFromPath(publicKeyPath string) (*stdRsa.PublicKey, error)
	ReadPrivateKeyFromPath(privateKeyPath string) (*stdRsa.PrivateKey, error)
	DecryptPKCS1v15(rand io.Reader, priv *stdRsa.PrivateKey, ciphertext []byte) ([]byte, error)
	EncryptPKCS1v15(rand io.Reader, pub *stdRsa.PublicKey, msg []byte) ([]byte, error)
	EncryptOAEP(hash hash.Hash, random io.Reader, pub *stdRsa.PublicKey, msg []byte, label []byte) ([]byte, error)
}

type AesService interface {
	EncryptCBC(key []byte, plaintext []byte) ([]byte, error)
	DecryptCBC(key []byte, ciphertext []byte) ([]byte, error)
	EncryptGCM(key []byte, plaintext []byte) ([]byte, error)
	DecryptGCM(key []byte, ciphertext []byte) ([]byte, error)
}
