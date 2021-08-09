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

func NewRekeyCommand(
	osExecutor os.OsExecutor,
	rsaSvc external_interfaces.RsaService,
	b64Svc external_interfaces.Base64Service,
	aesSvc external_interfaces.AesService,
) *cobra.Command {
	cmdInstance := &cobra.Command{
		Use: "rekey --old-private-key-path ./old-my-privatekey.pem " +
			"--new-public-key-path ./new-my-pubkey.pem " +
			"--in ./mysecret.txt " +
			"--out ./mysecret-enc.base64",
		Short: "Rekey (decrypt and encrypt using different keypair) a file/value",
		Long: "Rekey (decrypt and encrypt using different keypair) a file/value using " +
			"AES256-GCM symmetric encryption. " +
			"Public key must NOT originate from same private key, otherwise you probably want" +
			"to use `rotate` instead. " +
			"Passphrase is runtime randomly generated and encrypted with RSA asymmetric keypair.",
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
					"Enter encrypted payload to encrypt: ",
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

			payloadSerdeSvc := payload.NewSerdeService(b64Svc)
			oldEncryptedPayload, err := payloadSerdeSvc.Deserialize(inFileContent)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to deserialize old encrypted payload from `in` content",
				)
			}

			contentV1Svc := content.NewV1Service(b64Svc, aesSvc)

			oldPassphraseDecrypter := passphrase.NewDecryptionRsaPKCS1v15Service(oldPrivKey, rsaSvc)
			oldPayload, err := payload.NewDecryptionService(oldPassphraseDecrypter, contentV1Svc).Decrypt(oldEncryptedPayload)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to decrypt old encrypted payload "+
						"using `old_private_key_path` RSA key",
				)
			}

			passphraseSvc := passphrase.NewService()
			passphraseInstance, err := passphraseSvc.GeneratePassphrase(32)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to generate random AES passphrase",
				)
			}

			payloadInstance := payload.NewPayload(
				header.NewHeader(),
				passphraseInstance,
				content.NewContent(oldPayload.Content.Plaintext),
			)

			passphraseEncrypter := passphrase.NewEncryptionRsaPKCS1v15Service(rsaSvc, newPubKey)
			payloadEncrypter := payload.NewEncryptionService(passphraseEncrypter, contentV1Svc)

			newEncryptedPayload, err := payloadEncrypter.Encrypt(payloadInstance)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to encrypt payload",
				)
			}

			serializedEncryptedPayload, err := payloadSerdeSvc.Serialize(newEncryptedPayload)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to base64 serialize encrypted payload",
				)
			}

			outFilePath := cmdInstance.Flag("out").Value.String()
			if outFilePath == "" {
				fmt.Fprintln(osExecutor.Stdout(), "Rekeyed payload below:")

				// NOTE: Explicitly print as string representation
				fmt.Fprintln(osExecutor.Stdout(), string(serializedEncryptedPayload))
			} else {
				err := osExecutor.WriteFile(
					outFilePath,
					serializedEncryptedPayload,
					0644,
				)
				if err != nil {
					return stacktrace.Propagate(
						err,
						"failed to new write encrypted payload at out file path",
					)
				}
			}

			return nil
		},
	}

	cmdInstance.PersistentFlags().String(
		"old-private-key-path",
		"",
		"Path to RSA private key used to decrypt specified `in` path content.",
	)

	_ = cmdInstance.MarkPersistentFlagRequired("old-private-key-path")

	cmdInstance.PersistentFlags().String(
		"new-public-key-path",
		"",
		"Path to RSA public key used to encrypt runtime random generated passphrase.",
	)

	_ = cmdInstance.MarkPersistentFlagRequired("new-public-key-path")

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
