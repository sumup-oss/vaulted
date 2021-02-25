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

	"github.com/sumup-oss/vaulted/cli"
	"github.com/sumup-oss/vaulted/cmd/external_interfaces"
	"github.com/sumup-oss/vaulted/pkg/rsa"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

func NewRekeyCommand(
	osExecutor os.OsExecutor,
	rsaSvc *rsa.Service,
	encryptedPassphraseSvc external_interfaces.EncryptedPassphraseService,
	encryptedPayloadSvc external_interfaces.EncryptedPayloadService,
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

			oldEncryptedPayload, err := encryptedPayloadSvc.Deserialize(inFileContent)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to deserialize old encrypted payload from `in` content",
				)
			}

			oldPayload, err := encryptedPayloadSvc.Decrypt(oldPrivKey, oldEncryptedPayload)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to decrypt old encrypted payload "+
						"using `old_private_key_path` RSA key",
				)
			}

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
				content.NewContent(oldPayload.Content.Plaintext),
			)

			newEncryptedPayload, err := encryptedPayloadSvc.Encrypt(newPubKey, payload)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to encrypt payload",
				)
			}

			serializedEncryptedPayload, err := encryptedPayloadSvc.Serialize(newEncryptedPayload)
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
		"", "Path to the input file.",
	)

	cmdInstance.PersistentFlags().String(
		"out",
		"",
		"Path to the output file, that's going to be encrypted and encoded in base64.",
	)

	return cmdInstance
}
