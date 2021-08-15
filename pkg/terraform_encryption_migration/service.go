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
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/palantir/stacktrace"

	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

const (
	resourceType = "resource"
	// nolint:gosec
	vaultedVaultSecretResourceType = "vaulted_vault_secret"
)

type Service struct {
	terraformSvc terraformService
}

func NewTerraformEncryptionMigrationService(terraformSvc terraformService) *Service {
	return &Service{
		terraformSvc: terraformSvc,
	}
}

// RotateOrRekeyEncryptedTerraformResourceHcl parses and rotates a HCL terraform file
// with `vault_encrypted_secret` terraform resources encrypted that were using `encrypt` cmd.
// It decrypts, encrypts and replaces existing terraform `vaulted`.
// It does not lose/modify resources that are not `vault_encrypted_secret`.
func (s *Service) RotateOrRekeyEncryptedTerraformResourceHcl(
	hclParser hcl.Parser,
	hclBytes []byte,
	passphraseSvc *passphrase.Service,
	payloadSerdeSvc *payload.SerdeService,
	oldPayloadDecrypter PayloadDecrypter,
	newPayloadEncrypter PayloadEncrypter,
) (*hclwrite.File, error) {
	return s.terraformSvc.ModifyInPlaceHclAst(
		hclParser,
		hclBytes,
		s.rotateOrRekeyEncryptedTerraformResourceHclObjectItemVisitor(
			passphraseSvc,
			payloadSerdeSvc,
			oldPayloadDecrypter,
			newPayloadEncrypter,
		),
	)
}

func (s *Service) rotateOrRekeyEncryptedTerraformResourceHclObjectItemVisitor(
	passphraseSvc *passphrase.Service,
	payloadSerdeSvc *payload.SerdeService,
	oldPayloadDecrypter PayloadDecrypter,
	newPayloadEncrypter PayloadEncrypter,
) func(block *hclwrite.Block) error {
	return func(block *hclwrite.Block) error {
		if block.Type() != resourceType {
			return nil
		}

		// NOTE: We're only interested in
		//  "resource_type" "resource_name"`
		labels := block.Labels()
		if len(labels) != 2 {
			return nil
		}

		if labels[0] != vaultedVaultSecretResourceType {
			return nil
		}

		previousEncPayload, startTokenPos, endTokenPos, err := s.readHclQuoteLitAttr(
			block,
			"payload_json",
		)
		if err != nil {
			return stacktrace.NewError(
				"failed to read `payload_json` attr value for `%s.%s`",
				vaultedVaultSecretResourceType,
				labels[1],
			)
		}

		if len(previousEncPayload) == 0 {
			return stacktrace.NewError(
				"empty `payload_json` attr value for `%s.%s`",
				vaultedVaultSecretResourceType,
				labels[1],
			)
		}

		oldEncryptedPayload, err := payloadSerdeSvc.Deserialize(previousEncPayload)
		if err != nil {
			return stacktrace.NewError(
				"failed to deserialize `payload_json` attr's value for `%s.%s`",
				vaultedVaultSecretResourceType,
				labels[1],
			)
		}

		oldPayload, err := oldPayloadDecrypter.Decrypt(oldEncryptedPayload)
		if err != nil {
			return stacktrace.NewError(
				"failed to decrypt `payload_json` attr's value for `%s.%s`",
				vaultedVaultSecretResourceType,
				labels[1],
			)
		}

		newPassphrase, err := passphraseSvc.GeneratePassphrase(32)
		if err != nil {
			return stacktrace.NewError(
				"failed to generate new passphrase for `%s.%s`",
				vaultedVaultSecretResourceType,
				labels[1],
			)
		}

		// NOTE: Change passphrase with new one,
		// and encrypt the payload anew.
		oldPayload.Passphrase = newPassphrase

		newEncryptedPayload, err := newPayloadEncrypter.Encrypt(oldPayload)
		if err != nil {
			return stacktrace.NewError(
				"failed to encrypt new encrypted payload for `%s.%s`",
				vaultedVaultSecretResourceType,
				labels[1],
			)
		}

		serializedNewEncPayload, err := payloadSerdeSvc.Serialize(newEncryptedPayload)
		if err != nil {
			return stacktrace.NewError(
				"failed to serialize new encrypted payload for `%s.%s`",
				vaultedVaultSecretResourceType,
				labels[1],
			)
		}

		err = s.replaceHclQuoteLitAttr(block, "payload_json", serializedNewEncPayload, startTokenPos, endTokenPos)

		return stacktrace.Propagate(err, "failed to set new encrypted payload's `payload_json` attr for `%s.%s`",
			vaultedVaultSecretResourceType,
			labels[1],
		)
	}
}

func (s *Service) readHclQuoteLitAttr(block *hclwrite.Block, name string) ([]byte, int, int, error) {
	blockBody := block.Body()
	if blockBody == nil {
		return nil, -1, -1, stacktrace.NewError("value is not an object type. It's actually empty")
	}

	attr := blockBody.GetAttribute(name)
	if attr == nil {
		return nil, -1, -1, stacktrace.NewError("no HCL attr with given name")
	}

	expr := attr.Expr()
	tokens := expr.BuildTokens(nil)

	if len(expr.Variables()) > 0 {
		return nil, -1, -1, stacktrace.NewError(
			"attr uses variables/locals. It's unsafe to modify, remove the variables/locals usage",
		)
	}

	startingTokenPos := -1
	endTokenPos := -1

	for i, token := range tokens {
		if startingTokenPos == -1 {
			if token.Type == hclsyntax.TokenOQuote {
				// NOTE: Found potential start of string
				startingTokenPos = i
				continue
			}
		} else if token.Type == hclsyntax.TokenCQuote {
			endTokenPos = i
		}
	}

	if startingTokenPos == -1 {
		return nil, startingTokenPos, endTokenPos, stacktrace.NewError(
			"attr looks like it's not a string",
		)
	}

	if endTokenPos == -1 {
		return nil, startingTokenPos, endTokenPos, stacktrace.NewError(
			"attr looks like it's an incomplete/unclosed string",
		)
	}

	// NOTE: slice with +1 at start to exclude opening quotes
	stringTokens := tokens[startingTokenPos+1 : endTokenPos]

	return stringTokens.Bytes(), startingTokenPos, endTokenPos, nil
}

func (s *Service) replaceHclQuoteLitAttr(
	block *hclwrite.Block,
	name string,
	value []byte,
	startTokenPos,
	endTokenPos int,
) error {
	blockBody := block.Body()
	if blockBody == nil {
		return stacktrace.NewError("value is not an object type. It's actually empty")
	}

	attr := blockBody.GetAttribute(name)
	expr := attr.Expr()
	tokens := expr.BuildTokens(nil)

	cleanTokens := append(tokens[:startTokenPos+1], tokens[endTokenPos:]...)
	insertPos := startTokenPos + 1
	cleanTokens = append(cleanTokens[:insertPos+1], cleanTokens[insertPos:]...)
	cleanTokens[insertPos] = &hclwrite.Token{
		Type:  hclsyntax.TokenQuotedLit,
		Bytes: value,
		// NOTE: Prettify
		SpacesBefore: 1,
	}

	blockBody.SetAttributeRaw(name, cleanTokens)

	return nil
}
