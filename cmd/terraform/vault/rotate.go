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
	"github.com/sumup-oss/vaulted/internal/cli"
)

func NewRotateCommand(
	osExecutor os.OsExecutor,
	rsaSvc external_interfaces.RsaService,
	encryptedPassphraseSvc external_interfaces.EncryptedPassphraseService,
	v1EncryptedPayloadSvc external_interfaces.EncryptedPayloadService,
	hclSvc external_interfaces.HclService,
	tfEncryptionMigrationSvc external_interfaces.TerraformEncryptionMigrationService,
) *cobra.Command {
	cmdInstance := &cobra.Command{
		Use: "rotate " +
			"--public-key-path ./my-pubkey.pem " +
			"--private-key-path ./my-privatekey.pem " +
			"--in ./in.tf " +
			"--out ./out.tf",
		Short: "Rotate (decrypt and encrypt) existing terraform resources",
		Long: "Rotate (decrypt and encrypt) existing terraform resources using AES256-GCM encryption. " +
			"Public key must originate from same private key, otherwise you probably want" +
			"to use `rekey` instead. " +
			"Passfile runtime random generated and encrypted with RSA asymmetric keypair.",
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

			privateKeyPath := cmdInstance.Flag("private-key-path").Value.String()
			// NOTE: Read early to avoid needless decryption
			privKey, err := rsaSvc.ReadPrivateKeyFromPath(privateKeyPath)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to read specified private key",
				)
			}

			if pubKey.N.Cmp(privKey.N) != 0 || pubKey.E != privKey.E {
				return stacktrace.NewError(
					"specified public key does not originate from specified private key. " +
						"you're either misusing `rotate` or actually wanting to use " +
						"`rekey`. Check `rotate --help` and `rekey --help` to " +
						"understand the difference",
				)
			}

			var inFileContent []byte

			inFilePath := cmdInstance.Flag("in").Value.String()
			if inFilePath == "" {
				inFileContent, err = cli.ReadFromStdin(
					osExecutor,
					"Enter terraform content to rotate: ",
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
				privKey,
				pubKey,
				encryptedPassphraseSvc,
				v1EncryptedPayloadSvc,
			)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to rotate read terraform resources",
				)
			}
			return cli.WriteHCLout(
				osExecutor,
				cmdInstance.Flag("out").Value.String(),
				hclFile,
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
		"private-key-path",
		"",
		"Path to RSA private key used to decrypt specified `in` path content.",
	)
	//nolint:errcheck
	cmdInstance.MarkPersistentFlagRequired("private-key-path")

	cmdInstance.PersistentFlags().String(
		"in",
		"",
		"Path to the input file that contains terraform resources.",
	)

	cmdInstance.PersistentFlags().String(
		"out",
		"",
		"Path to the output file, that's going to contain rotated terraform resources.",
	)

	return cmdInstance
}
