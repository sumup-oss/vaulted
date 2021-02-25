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

package cmd

import (
	"fmt"

	"github.com/palantir/stacktrace"
	"github.com/spf13/cobra"
	"github.com/sumup-oss/go-pkgs/os"

	"github.com/sumup-oss/vaulted/internal/cli"
	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/rsa"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

func NewDecryptCommand(
	osExecutor os.OsExecutor,
) *cobra.Command {
	cmdInstance := &cobra.Command{
		Use:   "decrypt --private-key-path ./private.pem --in ./mysecret-enc.base64 --out ./mysecret.txt",
		Short: "Decrypt a file/value",
		Long: "Decrypt a file/value using AES-256GCM symmetric encryption. " +
			"Passphrase is encrypted with RSA asymmetric keypair.",
		RunE: func(cmdInstance *cobra.Command, args []string) error {
			privateKeyPath := cmdInstance.Flag("private-key-path").Value.String()

			rsaSvc := rsa.NewRsaService(osExecutor)
			// NOTE: Read early to avoid needless decryption
			privKey, err := rsaSvc.ReadPrivateKeyFromPath(privateKeyPath)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to read specified private key",
				)
			}

			inFilePathArg := cmdInstance.Flag("in").Value.String()

			var serializedEncryptedPayload []byte
			if inFilePathArg == "" {
				serializedEncryptedPayload, err = cli.ReadFromStdin(
					osExecutor,
					"Enter encrypted payload to decrypt:",
				)
				if err != nil {
					return stacktrace.Propagate(
						err,
						"failed to read encrypted payload from stdin",
					)
				}
			} else {
				serializedEncryptedPayload, err = osExecutor.ReadFile(inFilePathArg)
				if err != nil {
					return stacktrace.Propagate(
						err,
						"failed to read encrypted payload from specified file path",
					)
				}
			}

			base64Svc := base64.NewBase64Service()
			pkcs7Svc := pkcs7.NewPkcs7Service()
			aesSvc := aes.NewAesService(pkcs7Svc)

			encryptedPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				base64Svc,
				rsaSvc,
			)

			encryptedContentSvc := content.NewV1EncryptedContentService(
				base64Svc,
				aesSvc,
			)

			encryptedPayloadSvc := payload.NewEncryptedPayloadService(
				header.NewHeaderService(),
				encryptedPassphraseSvc,
				encryptedContentSvc,
			)

			encryptedPayload, err := encryptedPayloadSvc.Deserialize(serializedEncryptedPayload)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to deserialize base64-encoded encrypted payload",
				)
			}

			payload, err := encryptedPayloadSvc.Decrypt(privKey, encryptedPayload)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to decrypt encrypted payload using specified RSA key",
				)
			}

			outFilePath := cmdInstance.Flag("out").Value.String()
			if outFilePath == "" {
				fmt.Fprintln(osExecutor.Stdout(), "Decrypted payload below:")

				// NOTE: Explicitly print as string representation
				fmt.Fprintln(osExecutor.Stdout(), string(payload.Content.Plaintext))
			} else {
				err := osExecutor.WriteFile(
					outFilePath,
					payload.Content.Plaintext,
					0644,
				)
				if err != nil {
					return stacktrace.Propagate(
						err,
						"failed to write decrypted payload",
					)
				}
			}

			return nil
		},
	}

	cmdInstance.PersistentFlags().String(
		"private-key-path",
		"",
		"Path to RSA private key used to decrypt encrypted payload.",
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
