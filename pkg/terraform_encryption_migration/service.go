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
	"strings"

	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/token"
	"github.com/palantir/stacktrace"

	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/ini"
	"github.com/sumup-oss/vaulted/pkg/terraform"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

const (
	resourceTypeName                     = "resource"
	pathKeyName                          = "path"
	vaultEncryptedSecretResourceTypeName = "vault_encrypted_secret"
	vaultedVaultResourceTypeName         = "vaulted_vault_secret"
)

var (
	// HACK: HCL printer prints an equal sign in a `key = value` expression
	// only when the line is positive. The line number does not matter.
	hclEqualSign = token.Pos{
		Line: 1,
	}
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
) (*ast.File, error) {
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
) (*ast.File, error) {
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
) func(item *ast.ObjectItem) error {
	return func(item *ast.ObjectItem) error {
		// NOTE: We're only interested in
		// `"resource" "resource_type" "resource_name"`
		// HCL AST, which is exactly of length 3.
		if len(item.Keys) != 3 {
			return nil
		}

		// NOTE: Only resources of `vaulted_vault_secret` are rotatable
		if item.Keys[0].Token.Value() != resourceTypeName ||
			item.Keys[1].Token.Value() != vaultedVaultResourceTypeName {
			return nil
		}

		itemValObject, ok := item.Val.(*ast.ObjectType)
		if !ok {
			return stacktrace.NewError(
				"HCL resource `vaulted_vault_secret` `%s` value is not an object type. "+
					"It's actually %#v",
				item.Keys[2].Token.Text,
				item.Val,
			)
		}

		// NOTE: Expected `vaulted_vault_secret` resource to have content with keys for:
		// * path
		// * payload_json
		if len(itemValObject.List.Items) != 2 {
			return stacktrace.NewError(
				"HCL resource `vaulted_vault_secret` `%s` content is "+
					"likely malformed. Expected exactly 2 key-value pairs",
				item.Keys[2].Token.Text,
			)
		}

		var tfPath, tfPayloadJSON string

		for _, itemObj := range itemValObject.List.Items {
			var err error

			// NOTE: This is very dangerous due to implementation details of `Value`,
			// it panics if it's invalid.
			// Although it's not possible (in current terraform HCL revision) to have
			// a valid HCL that accepts a key that's non-string. it's good to have it in mind in future.
			itemObjKey, ok := itemObj.Keys[0].Token.Value().(string)
			if !ok {
				return stacktrace.Propagate(
					err,
					"non-string key for"+
						"`vaulted_vault_secret` `%s`. Key: %#v",
					item.Keys[2].Token.Text,
					itemObj.Keys[0].Token.Value(),
				)
			}

			if itemObjKey == pathKeyName {
				tfPath, err = s.getStringValueOfHCLobjectItemKey(itemObj)
				if err != nil {
					return stacktrace.Propagate(
						err,
						"failed to get `path` string value for "+
							"`vaulted_vault_secret` `%s`",
						item.Keys[2].Token.Text,
					)
				}
			} else if itemObjKey == "payload_json" {
				tfPayloadJSON, err = s.getStringValueOfHCLobjectItemKey(itemObj)
				if err != nil {
					return stacktrace.Propagate(
						err,
						"failed to get `payload_json` string value for "+
							"`vaulted_vault_secret` `%s`",
						item.Keys[2].Token.Text,
					)
				}
			}
		}

		if len(tfPath) == 0 {
			return stacktrace.NewError(
				"empty `path` string value for `vaulted_vault_secret` `%s`",
				item.Keys[2].Token.Text,
			)
		}

		if len(tfPayloadJSON) == 0 {
			return stacktrace.NewError(
				"empty `payload_json` string value for `vaulted_vault_secret` `%s`",
				item.Keys[2].Token.Text,
			)
		}

		oldEncryptedPayload, err := encryptedPayloadSvc.Deserialize([]byte(tfPayloadJSON))
		if err != nil {
			return stacktrace.NewError(
				"failed to deserialize `payload_json` for "+
					"`vaulted_vault_secret` `%s`",
				item.Keys[2].Token.Text,
			)
		}

		oldPayload, err := encryptedPayloadSvc.Decrypt(privKey, oldEncryptedPayload)
		if err != nil {
			return stacktrace.NewError(
				"failed to decrypt `payload_json` for "+
					"`vaulted_vault_secret` `%s`",
				item.Keys[2].Token.Text,
			)
		}

		newPassphrase, err := encryptedPassphraseSvc.GeneratePassphrase(32)
		if err != nil {
			return stacktrace.NewError(
				"failed to generate new passphrase for `vaulted_vault_secret` `%s`",
				item.Keys[2].Token.Text,
			)
		}

		// NOTE: Change passphrase with new one,
		// and encrypt the payload anew.
		oldPayload.Passphrase = newPassphrase

		encryptedPayload, err := encryptedPayloadSvc.Encrypt(pubKey, oldPayload)
		if err != nil {
			return stacktrace.NewError(
				"failed to encrypt new encrypted payload for `vaulted_vault_secret` `%s`",
				item.Keys[2].Token.Text,
			)
		}

		serializedEncryptedPayload, err := encryptedPayloadSvc.Serialize(encryptedPayload)
		if err != nil {
			return stacktrace.NewError(
				"failed to serialize new encrypted payload for `vaulted_vault_secret` `%s`",
				item.Keys[2].Token.Text,
			)
		}

		// NOTE: Overwrite content to new `payload_json` value.
		itemValObject.List.Items = s.writeVaultedVaultSecretASTitems(tfPath, serializedEncryptedPayload)
		return nil
	}
}

func (s *Service) migrateEncryptedTerraformResourceHclObjectItemVisitor(
	privKey *stdRsa.PrivateKey,
	pubKey *stdRsa.PublicKey,
	legacyEncryptedContentSvc EncryptedContentService,
	encryptedPassphraseSvc EncryptedPassphraseService,
	encryptedPayloadSvc EncryptedPayloadService,
) func(item *ast.ObjectItem) error {
	return func(item *ast.ObjectItem) error {
		// NOTE: We're only interested in
		// `"resource" "resource_type" "resource_name"`
		// HCL AST, which is exactly of length 3.
		if len(item.Keys) != 3 {
			return nil
		}

		// NOTE: Only resources of `vault_encrypted_secret` are migratable
		if item.Keys[0].Token.Value() != resourceTypeName ||
			item.Keys[1].Token.Value() != vaultEncryptedSecretResourceTypeName {
			return nil
		}

		itemValObject, ok := item.Val.(*ast.ObjectType)
		if !ok {
			return stacktrace.NewError(
				"HCL resource `vault_encrypted_secret` `%s` value is not an object type. "+
					"It's actually %#v",
				item.Keys[2].Token.Text,
				item.Val,
			)
		}

		// NOTE: Expected `vault_encrypted_secret` resource to have content with keys for:
		// * path
		// * encrypted_passphrase
		// * encrypted_data_json
		if len(itemValObject.List.Items) != 3 {
			return stacktrace.NewError(
				"HCL resource `vault_encrypted_secret` `%s` content is "+
					"likely malformed. Expected exactly 3 key-value pairs",
				item.Keys[2].Token.Text,
			)
		}

		var tfPath, tfEncryptedDataJson, tfEncryptedPassphrase string

		for _, itemObj := range itemValObject.List.Items {
			var err error

			// NOTE: This is very dangerous due to implementation details of `Value`,
			// it panics if it's invalid.
			// Although it's not possible (in current terraform HCL revision) to have
			// a valid HCL that accepts a key that's non-string. it's good to have it in mind in future.
			itemObjKey, ok := itemObj.Keys[0].Token.Value().(string)
			if !ok {
				return stacktrace.Propagate(
					err,
					"non-string key for"+
						"`vault_encrypted_secret` `%s`. Key: %#v",
					item.Keys[2].Token.Text,
					itemObj.Keys[0].Token.Value(),
				)
			}

			switch itemObjKey {
			case pathKeyName:
				tfPath, err = s.getStringValueOfHCLobjectItemKey(itemObj)
				if err != nil {
					return stacktrace.Propagate(
						err,
						"failed to get `path` string value for "+
							"`vault_encrypted_secret` `%s`",
						item.Keys[2].Token.Text,
					)
				}
			case "encrypted_data_json":
				tfEncryptedDataJson, err = s.getStringValueOfHCLobjectItemKey(itemObj)
				if err != nil {
					return stacktrace.Propagate(
						err,
						"failed to get `encrypted_data_json` string value for "+
							"`vault_encrypted_secret` `%s`",
						item.Keys[2].Token.Text,
					)
				}
			case "encrypted_passphrase":
				tfEncryptedPassphrase, err = s.getStringValueOfHCLobjectItemKey(itemObj)
				if err != nil {
					return stacktrace.Propagate(
						err,
						"failed to get `encrypted_passphrase` string value for "+
							"`vault_encrypted_secret` `%s`",
						item.Keys[2].Token.Text,
					)
				}
			}
		}

		if len(tfPath) == 0 {
			return stacktrace.NewError(
				"empty `path` string value for `vault_encrypted_secret` `%s`",
				item.Keys[2].Token.Text,
			)
		}

		if len(tfEncryptedDataJson) == 0 {
			return stacktrace.NewError(
				"empty `encrypted_data_json` string value for `vault_encrypted_secret` `%s`",
				item.Keys[2].Token.Text,
			)
		}

		if len(tfEncryptedPassphrase) == 0 {
			return stacktrace.NewError(
				"empty `encrypted_passphrase` string value for `vault_encrypted_secret` `%s`",
				item.Keys[2].Token.Text,
			)
		}

		legacyEncryptedPassphrase, err := encryptedPassphraseSvc.Deserialize(
			[]byte(tfEncryptedPassphrase),
		)
		if err != nil {
			return stacktrace.NewError(
				"failed to deserialize `encrypted_passphrase` for `vault_encrypted_secret` `%s`",
				item.Keys[2].Token.Text,
			)
		}

		legacyPassphrase, err := encryptedPassphraseSvc.Decrypt(privKey, legacyEncryptedPassphrase)
		if err != nil {
			return stacktrace.NewError(
				"failed to decrypt `encrypted_passphrase` for `vault_encrypted_secret` `%s`",
				item.Keys[2].Token.Text,
			)
		}

		legacyEncryptedContent, err := legacyEncryptedContentSvc.Deserialize([]byte(tfEncryptedDataJson))
		if err != nil {
			return stacktrace.NewError(
				"failed to deserialize `encrypted_data_json` for `vault_encrypted_secret` `%s`",
				item.Keys[2].Token.Text,
			)
		}

		content, err := legacyEncryptedContentSvc.Decrypt(legacyPassphrase, legacyEncryptedContent)
		if err != nil {
			return stacktrace.NewError(
				"failed to decrypt `encrypted_data_json` for `vault_encrypted_secret` `%s`",
				item.Keys[2].Token.Text,
			)
		}

		newPassphrase, err := encryptedPassphraseSvc.GeneratePassphrase(32)
		if err != nil {
			return stacktrace.NewError(
				"failed to generate new encrypted passphrase for `vault_encrypted_secret` `%s`",
				item.Keys[2].Token.Text,
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
				"failed to encrypt new encrypted payload for `vault_encrypted_secret` `%s`",
				item.Keys[2].Token.Text,
			)
		}

		serializedEncryptedPayload, err := encryptedPayloadSvc.Serialize(encryptedPayload)
		if err != nil {
			return stacktrace.NewError(
				"failed to serialize new encrypted payload for `vault_encrypted_secret` `%s`",
				item.Keys[2].Token.Text,
			)
		}

		// NOTE: Change the type of the resource to new one
		item.Keys[1].Token.Text = `"vaulted_vault_secret"`

		// NOTE: Start overwriting content to new encryption-usage resource `vaulted_vault_secret` format.
		itemValObject.List.Items = s.writeVaultedVaultSecretASTitems(tfPath, serializedEncryptedPayload)
		return nil
	}
}

func (s *Service) getStringValueOfHCLobjectItemKey(itemObj *ast.ObjectItem) (string, error) {
	literalType, ok := itemObj.Val.(*ast.LiteralType)
	if !ok {
		return "", stacktrace.NewError(
			"HCL resource value is not a literal type. It's a %#v.",
			itemObj.Val,
		)
	}

	if literalType.Token.Type != token.STRING {
		return "", stacktrace.NewError(
			"HCL resource value is not a string literal type. It's a %#v.",
			literalType.Token.Type,
		)
	}

	actualText := strings.TrimPrefix(literalType.Token.Text, `"`)
	actualText = strings.TrimSuffix(actualText, `"`)

	return actualText, nil
}

func (s *Service) ConvertIniContentToLegacyTerraformContent(
	passphraseLength int,
	iniContent *ini.Content,
	pubKey *stdRsa.PublicKey,
	encryptedPassphraseSvc EncryptedPassphraseService,
	encryptedContentSvc EncryptedContentService,
) (*terraform.Content, error) {
	terraformContent := terraform.NewTerraformContent()

	for name, section := range iniContent.SectionsByName {
		for _, sectionValue := range section.Values {
			resourceName := fmt.Sprintf("%s/%s", name, sectionValue.KeyName)
			terraformResource := terraform.NewTerraformResource(
				fmt.Sprintf(
					"vault_encrypted_secret_%s",
					strings.Replace(resourceName, "/", "_", -1),
				),
				"vault_encrypted_secret",
			)

			valueMap := map[string]interface{}{
				"value": sectionValue.Value,
			}

			dataJson, err := json.Marshal(valueMap)
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

			encryptedPassphrase, err := encryptedPassphraseSvc.Encrypt(pubKey, passphrase)
			if err != nil {
				return nil, stacktrace.Propagate(
					err,
					"failed to encrypt generated passphrase with specified public key",
				)
			}

			serializedEncPassphrase, err := encryptedPassphraseSvc.Serialize(encryptedPassphrase)
			if err != nil {
				return nil, stacktrace.Propagate(
					err,
					"failed to serialize encrypted passphrase",
				)
			}

			content := content.NewContent(dataJson)
			encryptedContent, err := encryptedContentSvc.Encrypt(passphrase, content)
			if err != nil {
				return nil, stacktrace.Propagate(
					err,
					"failed to encrypt content from section: %s, key: %s",
					name,
					sectionValue.KeyName,
				)
			}

			serializedEncContent, err := encryptedContentSvc.Serialize(encryptedContent)
			if err != nil {
				return nil, stacktrace.Propagate(
					err,
					"failed to serialize encrypted content",
				)
			}

			path := fmt.Sprintf("secret/%s", resourceName)
			terraformResource.Content = map[string]string{
				"path":                 path,
				"encrypted_data_json":  string(serializedEncContent),
				"encrypted_passphrase": string(serializedEncPassphrase),
			}

			terraformContent.AddResource(terraformResource)
		}
	}

	return terraformContent, nil
}

func (s *Service) ConvertIniContentToV1TerraformContent(
	passphraseLength int,
	iniContent *ini.Content,
	pubKey *stdRsa.PublicKey,
	encryptedPassphraseSvc EncryptedPassphraseService,
	encryptedPayloadSvc EncryptedPayloadService,
) (*terraform.Content, error) {
	terraformContent := terraform.NewTerraformContent()

	for name, section := range iniContent.SectionsByName {
		for _, sectionValue := range section.Values {
			resourceName := fmt.Sprintf("%s/%s", name, sectionValue.KeyName)
			terraformResource := terraform.NewTerraformResource(
				fmt.Sprintf(
					"vaulted_vault_secret_%s",
					strings.Replace(resourceName, "/", "_", -1),
				),
				"vaulted_vault_secret",
			)

			valueMap := map[string]interface{}{
				"value": sectionValue.Value,
			}

			dataJson, err := json.Marshal(valueMap)
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

			payload := payload.NewPayload(
				header.NewHeader(),
				passphrase,
				content.NewContent(dataJson),
			)
			encPayload, err := encryptedPayloadSvc.Encrypt(pubKey, payload)
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

			path := fmt.Sprintf("secret/%s", resourceName)
			terraformResource.Content = map[string]string{
				"path":         path,
				"payload_json": string(serializedEncPayload),
			}

			terraformContent.AddResource(terraformResource)
		}
	}

	return terraformContent, nil
}

func (s *Service) writeVaultedVaultSecretASTitems(path string, serializedPayloadJSON []byte) []*ast.ObjectItem {
	return []*ast.ObjectItem{
		{
			Keys: []*ast.ObjectKey{
				{
					Token: token.Token{
						Text: `"path"`,
						Type: token.STRING,
					},
				},
			},
			Assign: hclEqualSign,
			Val: &ast.LiteralType{
				Token: token.Token{
					Text: fmt.Sprintf(`"%s"`, path),
					Type: token.STRING,
				},
			},
		},
		{
			Keys: []*ast.ObjectKey{
				{
					Token: token.Token{
						Text: `"payload_json"`,
						Type: token.STRING,
					},
				},
			},
			Assign: hclEqualSign,
			Val: &ast.LiteralType{
				Token: token.Token{
					Text: fmt.Sprintf(`"%s"`, serializedPayloadJSON),
					Type: token.STRING,
				},
			},
		},
	}
}
