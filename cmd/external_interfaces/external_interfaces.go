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
	"io"

	goIni "github.com/go-ini/ini"
	"github.com/hashicorp/hcl/hcl/ast"

	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/ini"
	"github.com/sumup-oss/vaulted/pkg/terraform"
	"github.com/sumup-oss/vaulted/pkg/terraform_encryption_migration"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

type HclService interface {
	hcl.Printer
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
	Encrypt(publicKey *stdRsa.PublicKey, passphrase *passphrase.Passphrase) (*passphrase.EncryptedPassphrase, error)
	Decrypt(
		privateKey *stdRsa.PrivateKey,
		encryptedPassphrase *passphrase.EncryptedPassphrase,
	) (*passphrase.Passphrase, error)
}

type EncryptedPayloadService interface {
	Encrypt(publicKey *stdRsa.PublicKey, payload *payload.Payload) (*payload.EncryptedPayload, error)
	Decrypt(privateKey *stdRsa.PrivateKey, encryptedPayload *payload.EncryptedPayload) (*payload.Payload, error)
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

type TerraformService interface {
	TerraformContentToHCLfile(hclParser hcl.Parser, terraformContent *terraform.Content) (*ast.File, error)
	WriteHCLfile(hclPrinter hcl.Printer, hclFile *ast.File, output io.Writer) error
	TerraformResourceToHCLfile(hclParser hcl.Parser, resource terraform.Resource) (*ast.File, error)
}

type TerraformEncryptionMigrationService interface {
	ConvertIniContentToLegacyTerraformContent(
		passphraseLength int,
		iniContent *ini.Content,
		pubKey *stdRsa.PublicKey,
		encryptedPassphraseSvc terraform_encryption_migration.EncryptedPassphraseService,
		encryptedContentSvc terraform_encryption_migration.EncryptedContentService,
	) (*terraform.Content, error)
	ConvertIniContentToV1TerraformContent(
		passphraseLength int,
		iniContent *ini.Content,
		pubKey *stdRsa.PublicKey,
		encryptedPassphraseSvc terraform_encryption_migration.EncryptedPassphraseService,
		encryptedPayloadSvc terraform_encryption_migration.EncryptedPayloadService,
	) (*terraform.Content, error)
	MigrateEncryptedTerraformResourceHcl(
		hclParser hcl.Parser,
		hclBytes []byte,
		privKey *stdRsa.PrivateKey,
		pubKey *stdRsa.PublicKey,
		legacyEncryptedContentSvc terraform_encryption_migration.EncryptedContentService,
		encryptedPassphraseSvc terraform_encryption_migration.EncryptedPassphraseService,
		encryptedPayloadSvc terraform_encryption_migration.EncryptedPayloadService,
	) (*ast.File, error)
	RotateOrRekeyEncryptedTerraformResourceHcl(
		hclParser hcl.Parser,
		hclBytes []byte,
		privKey *stdRsa.PrivateKey,
		pubKey *stdRsa.PublicKey,
		encryptedPassphraseSvc terraform_encryption_migration.EncryptedPassphraseService,
		encryptedPayloadSvc terraform_encryption_migration.EncryptedPayloadService,
	) (*ast.File, error)
}

type RsaService interface {
	ReadPublicKeyFromPath(publicKeyPath string) (*stdRsa.PublicKey, error)
	ReadPrivateKeyFromPath(privateKeyPath string) (*stdRsa.PrivateKey, error)
	DecryptPKCS1v15(rand io.Reader, priv *stdRsa.PrivateKey, ciphertext []byte) ([]byte, error)
	EncryptPKCS1v15(rand io.Reader, pub *stdRsa.PublicKey, msg []byte) ([]byte, error)
}

type AesService interface {
	EncryptCBC(key []byte, plaintext []byte) ([]byte, error)
	DecryptCBC(key []byte, ciphertext []byte) ([]byte, error)
	EncryptGCM(key []byte, plaintext []byte) ([]byte, error)
	DecryptGCM(key []byte, ciphertext []byte) ([]byte, error)
}

type IniService interface {
	ReadIniAtPath(path string) (*goIni.File, error)
	ParseIniFileContents(file *goIni.File) *ini.Content
}
