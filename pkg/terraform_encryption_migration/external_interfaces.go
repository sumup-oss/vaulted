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

package terraform_encryption_migration

import (
	stdRsa "crypto/rsa"

	"github.com/hashicorp/hcl/hcl/ast"

	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

type terraformService interface {
	ModifyInPlaceHclAst(
		hclParser hcl.Parser,
		hclBytes []byte,
		objectItemVisitorFunc func(item *ast.ObjectItem) error,
	) (*ast.File, error)
}

type EncryptedContentService interface {
	Encrypt(passphrase *passphrase.Passphrase, content *content.Content) (*content.EncryptedContent, error)
	Decrypt(passphrase *passphrase.Passphrase, encryptedContent *content.EncryptedContent) (*content.Content, error)
	Serialize(encryptedContent *content.EncryptedContent) ([]byte, error)
	Deserialize(encoded []byte) (*content.EncryptedContent, error)
}

type EncryptedPassphraseService interface {
	Serialize(encryptedPassphrase *passphrase.EncryptedPassphrase) ([]byte, error)
	Encrypt(
		publicKey *stdRsa.PublicKey,
		passphrase *passphrase.Passphrase,
	) (*passphrase.EncryptedPassphrase, error)
	Deserialize(encoded []byte) (*passphrase.EncryptedPassphrase, error)
	Decrypt(
		privateKey *stdRsa.PrivateKey,
		encryptedPassphrase *passphrase.EncryptedPassphrase,
	) (*passphrase.Passphrase, error)
	GeneratePassphrase(length int) (*passphrase.Passphrase, error)
}

type EncryptedPayloadService interface {
	Encrypt(publicKey *stdRsa.PublicKey, payload *payload.Payload) (*payload.EncryptedPayload, error)
	Decrypt(privateKey *stdRsa.PrivateKey, encryptedPayload *payload.EncryptedPayload) (*payload.Payload, error)
	Serialize(encryptedPayload *payload.EncryptedPayload) ([]byte, error)
	Deserialize(encodedContent []byte) (*payload.EncryptedPayload, error)
}
