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
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/palantir/stacktrace"
	"github.com/zclconf/go-cty/cty"

	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/ini"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

const (
	resourceType                     = "resource"
	vaultEncryptedSecretResourceType = "vault_encrypted_secret"
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

// MigrateEncryptedTerraformResourceHcl parses and migrates a HCL terraform file
// with `vault_encrypted_secret` terraform resources encrypted that were using `legacy encrypt` cmd.
// It decrypts, encrypts and replaces existing terraform `vaulted`.
// It does not lose/modify resources that are not `vault_encrypted_secret`.
func (s *Service) MigrateEncryptedTerraformResourceHcl(
	hclParser hcl.Parser,
	hclBytes []byte,
	privKey *stdRsa.PrivateKey,
	pubKey *stdRsa.PublicKey,
	legacyEncryptedContentSvc EncryptedContentService,
	encryptedPassphraseSvc EncryptedPassphraseService,
	encryptedPayloadSvc EncryptedPayloadService,
) (*hclwrite.File, error) {
	return s.terraformSvc.ModifyInPlaceHclAst(
		hclParser,
		hclBytes,
		s.migrateEncryptedTerraformResourceHclObjectItemVisitor(
			privKey,
			pubKey,
			legacyEncryptedContentSvc,
			encryptedPassphraseSvc,
			encryptedPayloadSvc,
		),
	)
}

// RotateOrRekeyEncryptedTerraformResourceHcl parses and rotates a HCL terraform file
// with `vault_encrypted_secret` terraform resources encrypted that were using `encrypt` cmd.
// It decrypts, encrypts and replaces existing terraform `vaulted`.
// It does not lose/modify resources that are not `vault_encrypted_secret`.
func (s *Service) RotateOrRekeyEncryptedTerraformResourceHcl(
	hclParser hcl.Parser,
	hclBytes []byte,
	privKey *stdRsa.PrivateKey,
	pubKey *stdRsa.PublicKey,
	encryptedPassphraseSvc EncryptedPassphraseService,
	encryptedPayloadSvc EncryptedPayloadService,
) (*hclwrite.File, error) {
	return s.terraformSvc.ModifyInPlaceHclAst(
		hclParser,
		hclBytes,
		s.rotateOrRekeyEncryptedTerraformResourceHclObjectItemVisitor(
			privKey,
			pubKey,
			encryptedPassphraseSvc,
			encryptedPayloadSvc,
		),
	)
}

func (s *Service) rotateOrRekeyEncryptedTerraformResourceHclObjectItemVisitor(
	privKey *stdRsa.PrivateKey,
	pubKey *stdRsa.PublicKey,
	encryptedPassphraseSvc EncryptedPassphraseService,
	encryptedPayloadSvc EncryptedPayloadService,
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

		oldEncryptedPayload, err := encryptedPayloadSvc.Deserialize(previousEncPayload)
		if err != nil {
			return stacktrace.NewError(
				"failed to deserialize `payload_json` attr's value for `%s.%s`",
				vaultedVaultSecretResourceType,
				labels[1],
			)
		}

		oldPayload, err := encryptedPayloadSvc.Decrypt(privKey, oldEncryptedPayload)
		if err != nil {
			return stacktrace.NewError(
				"failed to decrypt `payload_json` attr's value for `%s.%s`",
				vaultedVaultSecretResourceType,
				labels[1],
			)
		}

		newPassphrase, err := encryptedPassphraseSvc.GeneratePassphrase(32)
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

		newEncryptedPayload, err := encryptedPayloadSvc.Encrypt(pubKey, oldPayload)
		if err != nil {
			return stacktrace.NewError(
				"failed to encrypt new encrypted payload for `%s.%s`",
				vaultedVaultSecretResourceType,
				labels[1],
			)
		}

		serializedNewEncPayload, err := encryptedPayloadSvc.Serialize(newEncryptedPayload)
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

func (s *Service) migrateEncryptedTerraformResourceHclObjectItemVisitor(
	privKey *stdRsa.PrivateKey,
	pubKey *stdRsa.PublicKey,
	legacyEncryptedContentSvc EncryptedContentService,
	encryptedPassphraseSvc EncryptedPassphraseService,
	encryptedPayloadSvc EncryptedPayloadService,
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

		if labels[0] != vaultEncryptedSecretResourceType {
			return nil
		}

		oldEncryptedDataJSON, _, _, err := s.readHclQuoteLitAttr(block, "encrypted_data_json")
		if err != nil {
			return stacktrace.NewError(
				"failed to read `encrypted_data_json` attr value for `%s.%s`",
				vaultEncryptedSecretResourceType,
				labels[1],
			)
		}

		if len(oldEncryptedDataJSON) == 0 {
			return stacktrace.NewError(
				"empty `encrypted_data_json` attr value for `%s.%s`",
				vaultEncryptedSecretResourceType,
				labels[1],
			)
		}

		oldEncryptedPassphrase, _, _, err := s.readHclQuoteLitAttr(block, "encrypted_passphrase")
		if err != nil {
			return stacktrace.NewError(
				"failed to read `encrypted_passphrase` attr value for `%s.%s`",
				vaultEncryptedSecretResourceType,
				labels[1],
			)
		}

		if len(oldEncryptedPassphrase) == 0 {
			return stacktrace.NewError(
				"empty `encrypted_passphrase` attr value for `%s.%s`",
				vaultEncryptedSecretResourceType,
				labels[1],
			)
		}

		legacyEncryptedPassphrase, err := encryptedPassphraseSvc.Deserialize(oldEncryptedPassphrase)
		if err != nil {
			return stacktrace.NewError(
				"failed to deserialize `encrypted_passphrase` attr value for `%s.%s`",
				vaultEncryptedSecretResourceType,
				labels[1],
			)
		}

		legacyPassphrase, err := encryptedPassphraseSvc.Decrypt(privKey, legacyEncryptedPassphrase)
		if err != nil {
			return stacktrace.NewError(
				"failed to decrypt `encrypted_passphrase` attr value for `%s.%s`",
				vaultEncryptedSecretResourceType,
				labels[1],
			)
		}

		legacyEncryptedContent, err := legacyEncryptedContentSvc.Deserialize(oldEncryptedDataJSON)
		if err != nil {
			return stacktrace.NewError(
				"failed to deserialize `encrypted_data_json` attr value for `%s.%s`",
				vaultEncryptedSecretResourceType,
				labels[1],
			)
		}

		content, err := legacyEncryptedContentSvc.Decrypt(legacyPassphrase, legacyEncryptedContent)
		if err != nil {
			return stacktrace.NewError(
				"failed to decrypt `encrypted_data_json` attr value for `%s.%s`",
				vaultEncryptedSecretResourceType,
				labels[1],
			)
		}

		newPassphrase, err := encryptedPassphraseSvc.GeneratePassphrase(32)
		if err != nil {
			return stacktrace.NewError(
				"failed to generate new encrypted passphrase for `%s.%s`",
				vaultEncryptedSecretResourceType,
				labels[1],
			)
		}

		payload := payload.NewPayload(
			header.NewHeader(),
			newPassphrase,
			content,
		)

		encryptedPayload, err := encryptedPayloadSvc.Encrypt(pubKey, payload)
		if err != nil {
			return stacktrace.NewError(
				"failed to encrypt new encrypted payload for `%s.%s`",
				vaultEncryptedSecretResourceType,
				labels[1],
			)
		}

		serializedEncryptedPayload, err := encryptedPayloadSvc.Serialize(encryptedPayload)
		if err != nil {
			return stacktrace.NewError(
				"failed to serialize new encrypted payload for `%s.%s`",
				vaultEncryptedSecretResourceType,
				labels[1],
			)
		}

		blockBody := block.Body()
		labels[0] = "vaulted_vault_secret"
		block.SetLabels(labels)

		// NOTE: Adapt to resource `vaulted_vault_secret` format.
		blockBody.RemoveAttribute("encrypted_data_json")
		blockBody.RemoveAttribute("encrypted_passphrase")
		blockBody.SetAttributeValue("encrypted_payload", cty.StringVal(string(serializedEncryptedPayload)))

		return nil
	}
}

func (s *Service) ConvertIniContentToV1ResourceHCL(
	passphraseLength int,
	iniContent *ini.Content,
	pubKey *stdRsa.PublicKey,
	encryptedPassphraseSvc EncryptedPassphraseService,
	encryptedPayloadSvc EncryptedPayloadService,
) (*hclwrite.File, error) {
	hclFile := hclwrite.NewEmptyFile()

	blocksByResourceName := make(map[string]*hclwrite.Block)
	sortedResourceNames := make([]string, 0)

	for name, section := range iniContent.SectionsByName {
		for _, sectionValue := range section.Values {
			iniPath := fmt.Sprintf("%s/%s", name, sectionValue.KeyName)
			resourceName := strings.ReplaceAll(iniPath, "/", "_")

			block := hclwrite.NewBlock(
				"resource",
				[]string{
					"vaulted_vault_secret",
					fmt.Sprintf(
						"vaulted_vault_secret_%s",
						resourceName,
					),
				},
			)
			valueMap := map[string]interface{}{
				"value": sectionValue.Value,
			}

			dataJSON, err := json.Marshal(valueMap)
			if err != nil {
				return nil, stacktrace.Propagate(
					err,
					"failed to marshal in JSON value for section: %s, key: %s",
					name,
					sectionValue.KeyName,
				)
			}

			passphrase, err := encryptedPassphraseSvc.GeneratePassphrase(passphraseLength)
			if err != nil {
				return nil, stacktrace.Propagate(
					err,
					"failed to generate random passphrase",
				)
			}

			payloadInstance := payload.NewPayload(
				header.NewHeader(),
				passphrase,
				content.NewContent(dataJSON),
			)

			encPayload, err := encryptedPayloadSvc.Encrypt(pubKey, payloadInstance)
			if err != nil {
				return nil, stacktrace.Propagate(
					err,
					"failed to encrypt content from section: %s, key: %s",
					name,
					sectionValue.KeyName,
				)
			}

			serializedEncPayload, err := encryptedPayloadSvc.Serialize(encPayload)
			if err != nil {
				return nil, stacktrace.Propagate(
					err,
					"failed to serialize encrypted payload",
				)
			}

			path := fmt.Sprintf("secret/%s", iniPath)

			blockBody := block.Body()
			blockBody.SetAttributeValue("path", cty.StringVal(path))
			blockBody.SetAttributeValue("payload_json", cty.StringVal(string(serializedEncPayload)))

			blocksByResourceName[resourceName] = block

			sortedResourceNames = append(sortedResourceNames, resourceName)
		}
	}

	// NOTE: Always add the resources alphabetically for consistency.
	sort.Strings(sortedResourceNames)

	for _, resourceName := range sortedResourceNames {
		block := blocksByResourceName[resourceName]
		hclFile.Body().AppendBlock(block)
	}

	return hclFile, nil
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
