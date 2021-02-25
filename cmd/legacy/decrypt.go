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
	"github.com/sumup-oss/vaulted/pkg/rsa"
)

func NewDecryptCommand(
	osExecutor os.OsExecutor,
	rsaSvc *rsa.Service,
	encryptedPassphraseSvc external_interfaces.EncryptedPassphraseService,
	encryptedContentSvc external_interfaces.EncryptedContentService,
) *cobra.Command {
	cmdInstance := &cobra.Command{
		Use: "decrypt --encrypted-passphrase <encrypted_passphrase> " +
			"--private-key-path ./my-key.pem " +
			"--in ./mysecret-enc.base64 " +
			"--out ./mysecret.txt",
		Short: "Decrypt a file/value",
		Long: "Decrypt a file/value using AES128-CBC symmetric encryption. " +
			"Passphrase is encrypted with RSA asymmetric keypair.",
		RunE: func(cmdInstance *cobra.Command, args []string) error {
			privateKeyPath := cmdInstance.Flag("private-key-path").Value.String()

			// NOTE: Read early to avoid needless decryption
			privKey, err := rsaSvc.ReadPrivateKeyFromPath(privateKeyPath)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to read specified private key",
				)
			}

			serializedEncryptedPassphraseArg := cmdInstance.Flag(
				"encrypted-passphrase",
			).Value.String()

			var serializedEncryptedPassphrase []byte
			if serializedEncryptedPassphraseArg == "" {
				serializedEncryptedPassphrase, err = cli.ReadFromStdin(
					osExecutor,
					"Enter encrypted passphrase:",
				)
				if err != nil {
					return stacktrace.Propagate(
						err,
						"failed to read encrypted passphrase from stdin",
					)
				}
			} else {
				serializedEncryptedPassphrase = []byte(serializedEncryptedPassphraseArg)
			}

			inFilePathArg := cmdInstance.Flag("in").Value.String()

			var serializedEncryptedContent []byte
			if inFilePathArg == "" {
				serializedEncryptedContent, err = cli.ReadFromStdin(
					osExecutor,
					"\nEnter encrypted value to decrypt:",
				)
				if err != nil {
					return stacktrace.Propagate(
						err,
						"failed to read encrypted content from stdin",
					)
				}
			} else {
				serializedEncryptedContent, err = osExecutor.ReadFile(inFilePathArg)
				if err != nil {
					return stacktrace.Propagate(
						err,
						"failed to read encrypted content from specified file path",
					)
				}
			}

			encryptedPassphrase, err := encryptedPassphraseSvc.Deserialize(serializedEncryptedPassphrase)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to deserialize base64-encoded encrypted passphrase",
				)
			}

			passphrase, err := encryptedPassphraseSvc.Decrypt(
				privKey,
				encryptedPassphrase,
			)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to decrypt encrypted passphrase using specified RSA private key",
				)
			}

			encryptedContent, err := encryptedContentSvc.Deserialize(serializedEncryptedContent)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to deserialize base64-encoded encrypted content",
				)
			}

			content, err := encryptedContentSvc.Decrypt(
				passphrase,
				encryptedContent,
			)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to decrypt encrypted content using decrypted passphrase",
				)
			}

			outFilePath := cmdInstance.Flag("out").Value.String()
			if outFilePath == "" {
				fmt.Fprintln(osExecutor.Stdout(), "")
				fmt.Fprintln(osExecutor.Stdout(), "Decrypted value below:")
				// NOTE: Explicitly print as string-representation
				fmt.Fprintln(osExecutor.Stdout(), string(content.Plaintext))
			} else {
				err := osExecutor.WriteFile(
					outFilePath,
					content.Plaintext,
					0644,
				)
				if err != nil {
					return stacktrace.Propagate(
						err,
						"failed to write decrypted content",
					)
				}
			}

			return nil
		},
	}

	cmdInstance.PersistentFlags().String(
		"encrypted-passphrase",
		"",
		"Value of the encrypted and base64 encoded passphrase.",
	)

	cmdInstance.PersistentFlags().String(
		"private-key-path",
		"",
		"Path to RSA private key used to decrypt passphrase of `encrypted-passphrase`",
	)
	//nolint:errcheck
	cmdInstance.MarkPersistentFlagRequired("private-key-path")

	cmdInstance.PersistentFlags().String(
		"in",
		"",
		"Path to the input file.",
	)
	cmdInstance.PersistentFlags().String(
		"out",
		"",
		"Path to the output file, that's going to be decrypted.",
	)

	return cmdInstance
}
