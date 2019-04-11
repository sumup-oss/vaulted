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

package terraform

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/palantir/stacktrace"
	"github.com/spf13/cobra"
	"github.com/sumup-oss/go-pkgs/os"

	"github.com/sumup-oss/vaulted/cli"
	"github.com/sumup-oss/vaulted/cmd/external_interfaces"
	"github.com/sumup-oss/vaulted/pkg/terraform"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

func NewNewResourceCommand(
	osExecutor os.OsExecutor,
	rsaSvc external_interfaces.RsaService,
	encryptedPassphraseSvc external_interfaces.EncryptedPassphraseService,
	encryptedPayloadSvc external_interfaces.EncryptedPayloadService,
	hclSvc external_interfaces.HclService,
	tfSvc external_interfaces.TerraformService,
) *cobra.Command {
	cmdInstance := &cobra.Command{
		Use: "new-resource --public-key-path ./my-pubkey.pem " +
			"--in ./mysecret.txt " +
			"--out ./mysecret.tf " +
			"--path secret/example-app/example-key " +
			"--resource-name example_app_example_key",
		Short: "Create new terraform vaulted vault secret resource",
		Long:  "Create new terraform vaulted vault secret resource",
		RunE: func(cmdInstance *cobra.Command, args []string) error {
			publicKeyPath := cmdInstance.Flag("public-key-path").Value.String()

			// NOTE: Read early to avoid needless encryption
			pubKey, err := rsaSvc.ReadPublicKeyFromPath(publicKeyPath)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to read specified public key",
				)
			}

			var inFileContent []byte

			inFilePath := cmdInstance.Flag("in").Value.String()
			if inFilePath == "" {
				inFileContent, err = cli.ReadFromStdin(
					osExecutor,
					"Enter plaintext value to encrypt: ",
				)
				if err != nil {
					return stacktrace.Propagate(
						err,
						"failed to read user input from stdin",
					)
				}
			} else {
				inFileContent, err = osExecutor.ReadFile(inFilePath)
				if err != nil {
					return stacktrace.Propagate(
						err,
						"failed to read specified in file path",
					)
				}
			}

			content := content.NewContent(inFileContent)

			passphrase, err := encryptedPassphraseSvc.GeneratePassphrase(32)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to generate random AES passphrase",
				)
			}

			payload := payload.NewPayload(
				header.NewHeader(),
				passphrase,
				content,
			)

			encryptedPayload, err := encryptedPayloadSvc.Encrypt(pubKey, payload)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to encrypt payload",
				)
			}

			serializedEncryptedPayload, err := encryptedPayloadSvc.Serialize(encryptedPayload)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to base64 serialize encrypted payload",
				)
			}

			var fullResourceName string

			resourceName := cmdInstance.Flag("resource-name").Value.String()
			outFilePath := cmdInstance.Flag("out").Value.String()

			if outFilePath == "" {
				fullResourceName = resourceName
			} else {
				resourcePrefix := strings.Replace(outFilePath, ".", "_", -1)
				resourcePrefix = strings.Replace(
					resourcePrefix,
					string(filepath.Separator),
					"_",
					-1,
				)
				fullResourceName = fmt.Sprintf("%s_%s", resourcePrefix, resourceName)
			}

			tfResource := terraform.NewTerraformResource(
				fullResourceName,
				"vaulted_vault_secret",
			)
			tfResource.Content["path"] = cmdInstance.Flag("path").Value.String()
			tfResource.Content["payload_json"] = string(serializedEncryptedPayload)

			hclFile, err := tfSvc.TerraformResourceToHCLfile(hclSvc, tfResource)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to convert terraform resource to HCL",
				)
			}

			return writeHCLout(
				osExecutor,
				outFilePath,
				hclSvc,
				hclFile,
				tfSvc,
			)
		},
	}

	cmdInstance.PersistentFlags().String(
		"public-key-path",
		"",
		"Path to RSA public key used to encrypt runtime random generated passphrase.",
	)
	//nolint:errcheck
	cmdInstance.MarkPersistentFlagRequired("public-key-path")

	cmdInstance.PersistentFlags().String(
		"path",
		"",
		"Terraform resource secret path to use in new resource",
	)
	//nolint:errcheck
	cmdInstance.MarkPersistentFlagRequired("path")

	cmdInstance.PersistentFlags().String(
		"resource-name",
		"",
		"Name of new terraform resource that will be part of full generated name",
	)
	//nolint:errcheck
	cmdInstance.MarkPersistentFlagRequired("resource-name")

	cmdInstance.PersistentFlags().String(
		"in",
		"",
		"Path to the input file.",
	)
	cmdInstance.PersistentFlags().String(
		"out",
		"",
		"Path to the output file, that's going to be created if not exists, otherwise appended to.",
	)

	return cmdInstance
}
