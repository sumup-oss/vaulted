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
	"context"
	stdRsa "crypto/rsa"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/palantir/stacktrace"
	"github.com/spf13/cobra"
	"github.com/sumup-oss/go-pkgs/os"

	"github.com/sumup-oss/vaulted/cmd/external_interfaces"
	"github.com/sumup-oss/vaulted/internal/cli"
	"github.com/sumup-oss/vaulted/pkg/aws"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

// nolint:lll
const decryptExample = `
  # Decryption using local RSA asymmetric keypair. This requires the "--in" to have been encrypted using local RSA public key.
  > vaulted decrypt --private-key-path ./my-pubkey.pem --in ./mysecret-enc.base64 --out ./mysecret.txt 

  # Decryption using AWS KMS asymmetric keypair. This requires the "--in" to have been encrypted using local AWS KMS asymmetric public key.
  # Make sure to set the correct AWS_REGION and AWS_PROFILE where the AWS KMS key is present.
  > AWS_REGION=eu-west-1 AWS_PROFILE=secretprofile vaulted decrypt --aws-kms-key-id=alias/yourkey  --in ./mysecret-enc.base64 --out ./mysecret.txt 
`

func NewDecryptCommand(
	osExecutor os.OsExecutor,
	rsaSvc external_interfaces.RsaService,
	b64Svc external_interfaces.Base64Service,
	aesSvc external_interfaces.AesService,
) *cobra.Command {
	cmdInstance := &cobra.Command{
		Use:   "decrypt --private-key-path ./private.pem --in ./mysecret-enc.base64 --out ./mysecret.txt",
		Short: "Decrypt a file/value",
		Long: "Decrypt a file/value using AES-256GCM symmetric encryption. " +
			"Passphrase is encrypted with RSA asymmetric keypair.",
		Example: decryptExample,
		RunE: func(cmdInstance *cobra.Command, args []string) error {
			privateKeyPath := cmdInstance.Flag("private-key-path").Value.String()
			awsKmsKeyID := cmdInstance.Flag("aws-kms-key-id").Value.String()
			awsRegion := cmdInstance.Flag("aws-region").Value.String()

			var privKey *stdRsa.PrivateKey
			var err error

			var decryptionService *payload.DecryptionService
			contentDecrypter := content.NewV1Service(b64Svc, aesSvc)

			if privateKeyPath != "" {
				privKey, err = rsaSvc.ReadPrivateKeyFromPath(privateKeyPath)
				if err != nil {
					return stacktrace.Propagate(
						err,
						"failed to read specified private key",
					)
				}

				decryptionService = payload.NewDecryptionService(
					passphrase.NewDecryptionRsaPKCS1v15Service(privKey, rsaSvc),
					contentDecrypter,
				)
			} else if awsKmsKeyID != "" {
				var awsSvc *aws.Service

				awsCfg, awsErr := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(awsRegion))
				if awsErr != nil {
					return stacktrace.Propagate(awsErr, "failed to load AWS config from environment")
				}

				awsSvc, awsErr = aws.NewService(&awsCfg)
				if awsErr != nil {
					return stacktrace.Propagate(awsErr, "failed to create aws service")
				}

				decryptionService = payload.NewDecryptionService(
					passphrase.NewDecryptionAwsKmsService(awsSvc, awsKmsKeyID),
					contentDecrypter,
				)
			}

			var serializedEncryptedPayload []byte

			// NOTE: Read early to avoid needless decryption
			inFilePathArg := cmdInstance.Flag("in").Value.String()
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

			payloadSerdeSvc := payload.NewSerdeService(b64Svc)

			encryptedPayload, err := payloadSerdeSvc.Deserialize(serializedEncryptedPayload)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to deserialize base64-encoded encrypted payload",
				)
			}

			payloadInstance, err := decryptionService.Decrypt(encryptedPayload)
			if err != nil {
				return stacktrace.Propagate(
					err,
					"failed to decrypt encrypted payload using specified RSA key",
				)
			}

			outFilePath := cmdInstance.Flag("out").Value.String()
			if outFilePath == "" {
				_, _ = fmt.Fprintln(osExecutor.Stdout(), "Decrypted payload below:")

				// NOTE: Explicitly print as string representation
				_, _ = fmt.Fprintln(osExecutor.Stdout(), string(payloadInstance.Content.Plaintext))

				return nil
			}

			err = osExecutor.WriteFile(
				outFilePath,
				payloadInstance.Content.Plaintext,
				0644,
			)
			return stacktrace.Propagate(
				err,
				"failed to write decrypted payload",
			)
		},
	}

	cmdInstance.PersistentFlags().String(
		"private-key-path",
		"",
		"Path to RSA private key used to decrypt encrypted payload.",
	)

	cmdInstance.PersistentFlags().String(
		"aws-kms-key-id",
		"",
		"AWS Asymmetric Customer Managed Key ID",
	)

	cmdInstance.PersistentFlags().String(
		"aws-region",
		"",
		"AWS Region to use for KMS. Can also be provided by `AWS_REGION` environment variable.",
	)

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
