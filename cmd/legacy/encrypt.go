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

package legacy

import (
	"fmt"

	"github.com/palantir/stacktrace"
	"github.com/spf13/cobra"
	"github.com/sumup-oss/go-pkgs/os"

	"github.com/sumup-oss/vaulted/cmd/external_interfaces"
	"github.com/sumup-oss/vaulted/internal/cli"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
)

func NewEncryptCommand(
	osExecutor os.OsExecutor,
	rsaSvc external_interfaces.RsaService,
	encryptedPassphraseSvc external_interfaces.EncryptedPassphraseService,
	encryptedContentSvc external_interfaces.EncryptedContentService,
) *cobra.Command {
	cmdInstance := &cobra.Command{
		Use:   "encrypt --public-key-path ./my-pubkey.pem --in ./mysecret.txt --out ./mysecret-enc.base64",
		Short: "Encrypt a file/value",
		Long: "Encrypt a file/value using AES128-CBC symmetric encryption. " +
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

			passphrase, err := encryptedPassphraseSvc.GeneratePassphrase(16)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to generate random AES passphrase",
				)
			}

			encryptedContent, err := encryptedContentSvc.Encrypt(passphrase, content)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to encrypt content using AES passphrase",
				)
			}

			encryptedPassphrase, err := encryptedPassphraseSvc.Encrypt(pubKey, passphrase)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to encrypt AES passphrase using RSA public key",
				)
			}

			serializedEncryptedPassphrase, err := encryptedPassphraseSvc.Serialize(encryptedPassphrase)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to base64 serialize encrypted passphrase",
				)
			}

			fmt.Fprintln(osExecutor.Stdout(), "Encrypted passphrase below:")
			// NOTE: Explicitly print as string representation
			fmt.Fprintln(osExecutor.Stdout(), string(serializedEncryptedPassphrase))

			serializedEncryptedContent, err := encryptedContentSvc.Serialize(encryptedContent)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to base64 serialize encrypted content",
				)
			}

			outFilePath := cmdInstance.Flag("out").Value.String()
			if outFilePath == "" {
				fmt.Fprintln(osExecutor.Stdout(), "")
				fmt.Fprintln(osExecutor.Stdout(), "Encrypted value below:")
				// NOTE: Explicitly print as string representation
				fmt.Fprintln(osExecutor.Stdout(), string(serializedEncryptedContent))
			} else {
				err := osExecutor.WriteFile(
					outFilePath,
					serializedEncryptedContent,
					0644,
				)
				if err != nil {
					return stacktrace.Propagate(
						err,
						"failed to write encrypted content at out file path",
					)
				}
			}

			return nil
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
		"", "Path to the input file.",
	)

	cmdInstance.PersistentFlags().String(
		"out",
		"",
		"Path to the output file, that's going to be encrypted and encoded in base64.",
	)

	return cmdInstance
}
