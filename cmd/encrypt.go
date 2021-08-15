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

	"github.com/sumup-oss/vaulted/cmd/external_interfaces"
	"github.com/sumup-oss/vaulted/internal/cli"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

var knownTypes = []string{
	"local-rsa",
	"aws-kms-asym",
}

const encryptExample = `
  # Encryption using local RSA asymmetric keypair
  > vaulted encrypt --public-key-path ./my-pubkey.pem --in ./mysecret.txt --out ./mysecret-enc.base64
  # Encryption using AWS KMS asymmetric keypair. Prerequisite: public key is already locally downloaded
  > vaulted encrypt --type=aws-kms-asym --public-key-path ./my-pubkey.pem --in ./mysecret.txt --out ./mysecret-enc.base64
`

func NewEncryptCommand(
	osExecutor os.OsExecutor,
	rsaSvc external_interfaces.RsaService,
	b64Svc external_interfaces.Base64Service,
	aesSvc external_interfaces.AesService,
) *cobra.Command {
	cmdInstance := &cobra.Command{
		Use:   "encrypt --public-key-path ./my-pubkey.pem --in ./mysecret.txt --out ./mysecret-enc.base64",
		Short: "Encrypt a file/value",
		Long: "Encrypt a file/value using AES256-GCM symmetric encryption. " +
			"Passphrase is runtime randomly generated and encrypted with RSA asymmetric keypair.",
		Example: encryptExample,
		RunE: func(cmdInstance *cobra.Command, args []string) error {
			publicKeyPath := cmdInstance.Flag("public-key-path").Value.String()

			// NOTE: Read early to make sure the RSA key is valid
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

			contentInstance := content.NewContent(inFileContent)

			passphraseSvc := passphrase.NewService()

			generatedPassphrase, err := passphraseSvc.GeneratePassphrase(32)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to generate random AES passphrase",
				)
			}

			payloadInstance := payload.NewPayload(
				header.NewHeader(),
				generatedPassphrase,
				contentInstance,
			)

			var encryptionService *payload.EncryptionService
			contentEncrypter := content.NewV1Service(b64Svc, aesSvc)

			encryptionType := cmdInstance.Flag("type").Value.String()
			switch encryptionType {
			case "local-rsa":
				passphraseEncrypter := passphrase.NewEncryptionRsaPKCS1v15Service(rsaSvc, pubKey)
				encryptionService = payload.NewEncryptionService(passphraseEncrypter, contentEncrypter)
			case "aws-kms-asym":
				passphraseEncrypter := passphrase.NewEncRsaOaepService(rsaSvc, pubKey)
				encryptionService = payload.NewEncryptionService(passphraseEncrypter, contentEncrypter)
			default:
				return stacktrace.NewError("unsupported `type` specified. Supported values: %#v", knownTypes)
			}

			serdeSvc := payload.NewSerdeService(b64Svc)
			encryptedPayload, err := encryptionService.Encrypt(payloadInstance)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to encrypt payload",
				)
			}

			serializedEncryptedPayload, err := serdeSvc.Serialize(encryptedPayload)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to base64 serialize encrypted payload",
				)
			}

			outFilePath := cmdInstance.Flag("out").Value.String()
			if outFilePath == "" {
				_, _ = fmt.Fprintln(osExecutor.Stdout(), "Encrypted payload below:")

				// NOTE: Explicitly print as string representation
				_, _ = fmt.Fprintln(osExecutor.Stdout(), string(serializedEncryptedPayload))
			} else {
				err := osExecutor.WriteFile(
					outFilePath,
					serializedEncryptedPayload,
					0644,
				)
				if err != nil {
					return stacktrace.Propagate(
						err,
						"failed to write encrypted payload at out file path",
					)
				}
			}

			return nil
		},
	}

	cmdInstance.PersistentFlags().String(
		"type",
		"local-rsa",
		fmt.Sprintf("Encryption type that must match the `decrypt` cmd's `type`. Valid value is one of %#v", knownTypes),
	)

	cmdInstance.PersistentFlags().String(
		"public-key-path",
		"",
		"Path to RSA public key used to encrypt runtime random generated passphrase.",
	)

	_ = cmdInstance.MarkPersistentFlagRequired("public-key-path")

	cmdInstance.PersistentFlags().String(
		"in",
		"",
		"Path to the input file.",
	)

	cmdInstance.PersistentFlags().String(
		"out",
		"",
		"Path to the output file, that's going to be encrypted and encoded in base64.",
	)

	return cmdInstance
}
