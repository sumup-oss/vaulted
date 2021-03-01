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

package vault

import (
	"github.com/palantir/stacktrace"
	"github.com/spf13/cobra"
	"github.com/sumup-oss/go-pkgs/os"

	"github.com/sumup-oss/vaulted/cmd/external_interfaces"
)

func NewIniCommand(
	osExecutor os.OsExecutor,
	rsaSvc external_interfaces.RsaService,
	iniSvc external_interfaces.IniService,
	encryptedPassphraseSvc external_interfaces.EncryptedPassphraseService,
	encryptedPayloadSvc external_interfaces.EncryptedPayloadService,
	hclSvc external_interfaces.HclService,
	terraformEncryptionMigrationSvc external_interfaces.TerraformEncryptionMigrationService,
) *cobra.Command {
	cmdInstance := &cobra.Command{
		Use:   "ini --public-key-path ./my-key.pem --in ./secrets.ini --out ./secrets.tf",
		Short: "Convert an INI file to Terraform file",
		Long: "Convert an INI file to Terraform file with vaulted_vault_secret resources, " +
			"encrypted with AES256-GCM symmetric encryption. " +
			"Passfile is random generated during runtime and encrypted with RSA asymmetric keypair.",
		RunE: func(cmdInstance *cobra.Command, _ []string) error {
			publicKeyPath := cmdInstance.Flag("public-key-path").Value.String()
			pubKey, err := rsaSvc.ReadPublicKeyFromPath(publicKeyPath)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to read specified public key",
				)
			}

			inPath := cmdInstance.Flag("in").Value.String()

			iniFile, err := iniSvc.ReadIniAtPath(inPath)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to read specified INI file",
				)
			}

			iniContent := iniSvc.ParseIniFileContents(iniFile)

			hclFile, err := terraformEncryptionMigrationSvc.ConvertIniContentToV1ResourceHCL(
				32,
				iniContent,
				pubKey,
				encryptedPassphraseSvc,
				encryptedPayloadSvc,
			)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to transform INI content to HCL",
				)
			}

			outPath := cmdInstance.Flag("out").Value.String()
			err = osExecutor.WriteFile(outPath, hclFile.Bytes(), 0755)
			return stacktrace.Propagate(
				err,
				"failed to write HCL to file",
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
		"in",
		"",
		"Path to the input INI file",
	)
	//nolint:errcheck
	cmdInstance.MarkPersistentFlagRequired("in")

	cmdInstance.PersistentFlags().String(
		"out",
		"",
		"Path to the output terraform file",
	)
	//nolint:errcheck
	cmdInstance.MarkPersistentFlagRequired("out")

	return cmdInstance
}
