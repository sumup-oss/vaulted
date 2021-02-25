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
)

func NewRotateCommand(
	osExecutor os.OsExecutor,
	rsaSvc *rsa.Service,
	encryptedPassphraseSvc external_interfaces.EncryptedPassphraseService,
	encryptedPayloadSvc external_interfaces.EncryptedPayloadService,
) *cobra.Command {
	cmdInstance := &cobra.Command{
		Use: "rotate " +
			"--public-key-path ./my-pubkey.pem " +
			"--private-key-path ./my-privatekey.pem " +
			"--in ./mysecret.txt " +
			"--out ./mysecret-enc.base64",
		Short: "Rotate (decrypt and encrypt) a file/value",
		Long: "Rotate (decrypt and encrypt) a file/value using AES256-GCM symmetric encryption. " +
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

			encryptedPayload, err := encryptedPayloadSvc.Deserialize(inFileContent)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to deserialize encrypted payload from `in` content",
				)
			}

			payload, err := encryptedPayloadSvc.Decrypt(privKey, encryptedPayload)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to decrypt encrypted payload using `private-key-path` RSA key",
				)
			}

			passphrase, err := encryptedPassphraseSvc.GeneratePassphrase(32)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to generate random AES passphrase",
				)
			}

			// NOTE: Change passphrase with new one,
			// and encrypt the payload anew.
			payload.Passphrase = passphrase

			newEncryptedPayload, err := encryptedPayloadSvc.Encrypt(pubKey, payload)
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
				fmt.Fprintln(osExecutor.Stdout(), "Rotated payload below:")

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
						"failed to write encrypted payload at out file path",
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
		"private-key-path",
		"",
		"Path to RSA private key used to decrypt specified `in` path content.",
	)
	//nolint:errcheck
	cmdInstance.MarkPersistentFlagRequired("private-key-path")

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
