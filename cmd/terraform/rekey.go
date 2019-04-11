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
	"github.com/palantir/stacktrace"
	"github.com/spf13/cobra"
	"github.com/sumup-oss/go-pkgs/os"

	"github.com/sumup-oss/vaulted/cli"
	"github.com/sumup-oss/vaulted/cmd/external_interfaces"
)

func NewRekeyCommand(
	osExecutor os.OsExecutor,
	rsaSvc external_interfaces.RsaService,
	encryptedPassphraseSvc external_interfaces.EncryptedPassphraseService,
	v1EncryptedPayloadSvc external_interfaces.EncryptedPayloadService,
	hclSvc external_interfaces.HclService,
	tfSvc external_interfaces.TerraformService,
	tfEncryptionMigrationSvc external_interfaces.TerraformEncryptionMigrationService,
) *cobra.Command {
	cmdInstance := &cobra.Command{
		Use: "rekey --old-private-key-path ./old-my-privatekey.pem " +
			"--new-public-key-path ./new-my-pubkey.pem " +
			"--in ./mysecret.txt " +
			"--out ./mysecret.tf",
		Short: "Rekey (decrypt and encrypt using different keypair) existing terraform resources",
		Long: "Rekey (decrypt and encrypt using different keypair) existing terraform resources using " +
			"AES256-GCM symmetric encryption. " +
			"Public key must NOT originate from same private key, otherwise you probably want" +
			"to use `rotate` instead. " +
			"Passfile runtime random generated and encrypted with RSA asymmetric keypair.",
		RunE: func(cmdInstance *cobra.Command, args []string) error {
			oldPrivateKeyPath := cmdInstance.Flag("old-private-key-path").Value.String()
			// NOTE: Read early to avoid needless decryption
			oldPrivKey, err := rsaSvc.ReadPrivateKeyFromPath(oldPrivateKeyPath)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to read specified old private key",
				)
			}

			newPublicKeyPath := cmdInstance.Flag("new-public-key-path").Value.String()

			// NOTE: Read early to avoid needless encryption
			newPubKey, err := rsaSvc.ReadPublicKeyFromPath(newPublicKeyPath)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to read specified new public key",
				)
			}

			if newPubKey.N.Cmp(oldPrivKey.N) == 0 && newPubKey.E == oldPrivKey.E {
				return stacktrace.NewError(
					"specified public key originates from specified private key. " +
						"you're either misusing `rekey` or actually wanting to use " +
						"`rotate`. Check `rotate --help` and `rekey --help` to " +
						"understand the difference",
				)
			}

			var inFileContent []byte

			inFilePath := cmdInstance.Flag("in").Value.String()
			if inFilePath == "" {
				inFileContent, err = cli.ReadFromStdin(
					osExecutor,
					"Enter terraform content to rekey: ",
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

			hclFile, err := tfEncryptionMigrationSvc.RotateOrRekeyEncryptedTerraformResourceHcl(
				hclSvc,
				inFileContent,
				oldPrivKey,
				newPubKey,
				encryptedPassphraseSvc,
				v1EncryptedPayloadSvc,
			)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to rekey read terraform resources",
				)
			}
			return writeHCLout(
				osExecutor,
				cmdInstance.Flag("out").Value.String(),
				hclSvc,
				hclFile,
				tfSvc,
			)
		},
	}

	cmdInstance.PersistentFlags().String(
		"old-private-key-path",
		"",
		"Path to RSA private key used to decrypt specified `in` path content.",
	)
	//nolint:errcheck
	cmdInstance.MarkPersistentFlagRequired("old-private-key-path")

	cmdInstance.PersistentFlags().String(
		"new-public-key-path",
		"",
		"Path to RSA public key used to encrypt runtime random generated passphrase.",
	)
	//nolint:errcheck
	cmdInstance.MarkPersistentFlagRequired("new-public-key-path")

	cmdInstance.PersistentFlags().String(
		"in",
		"",
		"Path to the input file that contains terraform resources.",
	)

	cmdInstance.PersistentFlags().String(
		"out",
		"",
		"Path to the output file, that's going to be contain rekeyed terraform content.",
	)

	return cmdInstance
}
