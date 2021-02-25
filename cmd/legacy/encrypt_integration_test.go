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
	"bytes"
	"crypto/rand"
	stdRsa "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/sumup-oss/go-pkgs/os"
	"github.com/sumup-oss/go-pkgs/os/ostest"
	"github.com/sumup-oss/go-pkgs/testutils"
	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/rsa"
	"github.com/sumup-oss/vaulted/pkg/rsa/test"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	testContent "github.com/sumup-oss/vaulted/pkg/vaulted/content/test"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
	testEncPassphraseService "github.com/sumup-oss/vaulted/pkg/vaulted/passphrase/test"
)

func TestEncryptCommand_Execute(t *testing.T) {
	t.Run(
		"with no arguments, it returns error",
		func(t *testing.T) {
			outputBuff := &bytes.Buffer{}

			osExecutor := ostest.NewFakeOsExecutor(t)

			b64Svc := base64.NewBase64Service()
			rsaSvc := rsa.NewRsaService(osExecutor)
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)
			encContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)

			cmdInstance := NewEncryptCommand(osExecutor, rsaSvc, encPassphraseSvc, encContentSvc)

			_, err := testutils.RunCommandInSameProcess(
				cmdInstance,
				[]string{},
				outputBuff,
			)

			expectedOutput := `Error: required flag(s) "public-key-path" not set
Usage:
  encrypt --public-key-path ./my-pubkey.pem --in ./mysecret.txt --out ./mysecret-enc.base64 [flags]

Flags:
  -h, --help                     help for encrypt
      --in string                Path to the input file.
      --out string               Path to the output file, that's going to be encrypted and encoded in base64.
      --public-key-path string   Path to RSA public key used to encrypt runtime random generated passphrase.

`
			assert.Equal(t, expectedOutput, outputBuff.String())
			assert.Equal(t, `required flag(s) "public-key-path" not set`, err.Error())

			osExecutor.AssertExpectations(t)
		},
	)

	t.Run(
		"with 'public-key-path', 'in', 'out' flags specified, but reading the 'public-key-path' fails, "+
			"it returns error",
		func(t *testing.T) {
			publicKeyPathFlag := "/tmp/example.pub"

			outputBuff := &bytes.Buffer{}
			osExecutor := ostest.NewFakeOsExecutor(t)

			fakeError := errors.New("readpublickeyfrompathError")
			rsaSvc := &test.MockRsaService{}
			rsaSvc.On(
				"ReadPublicKeyFromPath",
				publicKeyPathFlag,
			).Return(nil, fakeError)

			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)
			encContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)

			cmdInstance := NewEncryptCommand(osExecutor, rsaSvc, encPassphraseSvc, encContentSvc)

			cmdArgs := []string{
				fmt.Sprintf("--public-key-path=%s", publicKeyPathFlag),
				"--in=/tmp/example.in",
				"--out=/tmp/example.out",
			}

			_, err := testutils.RunCommandInSameProcess(
				cmdInstance,
				cmdArgs,
				outputBuff,
			)

			assert.Contains(t, err.Error(), "failed to read specified public key")

			osExecutor.AssertExpectations(t)
			rsaSvc.AssertExpectations(t)
		},
	)

	t.Run(
		"with 'public-key-path', 'in', 'out' flags specified, but reading the file at 'in' path fails, "+
			"it returns error",
		func(t *testing.T) {
			tmpDir := testutils.TestCwd(t, "vaulted")

			outputBuff := &bytes.Buffer{}
			realOsExecutor := &os.RealOsExecutor{}

			inPathFlag := filepath.Join(tmpDir, "in.raw")

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			pubkeyPathArg := filepath.Join(tmpDir, "key.pub")

			pubkeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			require.Nil(t, err)

			pubkeyPemBytes := pem.EncodeToMemory(
				&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pubkeyBytes,
				},
			)

			err = realOsExecutor.WriteFile(pubkeyPathArg, pubkeyPemBytes, 0644)
			require.Nil(t, err)

			fakeError := errors.New("readfileError")
			osExecutor := ostest.NewFakeOsExecutor(t)
			osExecutor.On(
				"ReadFile",
				inPathFlag,
			).Return(nil, fakeError)

			rsaSvc := rsa.NewRsaService(realOsExecutor)
			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)
			encContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)

			cmdInstance := NewEncryptCommand(osExecutor, rsaSvc, encPassphraseSvc, encContentSvc)

			cmdArgs := []string{
				fmt.Sprintf("--public-key-path=%s", pubkeyPathArg),
				fmt.Sprintf("--in=%s", inPathFlag),
				"--out=/tmp/example.out",
			}

			_, err = testutils.RunCommandInSameProcess(
				cmdInstance,
				cmdArgs,
				outputBuff,
			)

			assert.Contains(t, err.Error(), "failed to read specified in file path")

			osExecutor.AssertExpectations(t)
		},
	)

	t.Run(
		"with 'public-key-path', 'in', 'out' flags specified, but generating a passphrase fails, "+
			"it returns error",
		func(t *testing.T) {
			tmpDir := testutils.TestCwd(t, "vaulted")

			outputBuff := &bytes.Buffer{}
			realOsExecutor := &os.RealOsExecutor{}

			inPathFlag := filepath.Join(tmpDir, "in.raw")
			inFileContent := []byte("mysecret")
			err := realOsExecutor.WriteFile(inPathFlag, inFileContent, 0644)
			require.Nil(t, err)

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			pubkeyPathArg := filepath.Join(tmpDir, "key.pub")

			pubkeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			require.Nil(t, err)

			pubkeyPemBytes := pem.EncodeToMemory(
				&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pubkeyBytes,
				},
			)

			err = realOsExecutor.WriteFile(pubkeyPathArg, pubkeyPemBytes, 0644)
			require.Nil(t, err)

			fakeError := errors.New("generatepassphraseError")

			rsaSvc := rsa.NewRsaService(realOsExecutor)
			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			encPassphraseSvc := &testEncPassphraseService.MockEncryptedPassphraseService{}
			encPassphraseSvc.On(
				"GeneratePassphrase",
				16,
			).Return(nil, fakeError)

			encContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)

			cmdInstance := NewEncryptCommand(realOsExecutor, rsaSvc, encPassphraseSvc, encContentSvc)

			cmdArgs := []string{
				fmt.Sprintf("--public-key-path=%s", pubkeyPathArg),
				fmt.Sprintf("--in=%s", inPathFlag),
				"--out=/tmp/example.out",
			}

			_, err = testutils.RunCommandInSameProcess(
				cmdInstance,
				cmdArgs,
				outputBuff,
			)

			assert.Contains(t, err.Error(), "failed to generate random AES passphrase")
		},
	)

	t.Run(
		"with 'public-key-path', 'in', 'out' flags specified, but encrypting content fails, "+
			"it returns error",
		func(t *testing.T) {
			tmpDir := testutils.TestCwd(t, "vaulted")

			outputBuff := &bytes.Buffer{}
			realOsExecutor := &os.RealOsExecutor{}

			inPathFlag := filepath.Join(tmpDir, "in.raw")
			inFileContent := []byte("mysecret")
			err := realOsExecutor.WriteFile(inPathFlag, inFileContent, 0644)
			require.Nil(t, err)

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			pubkeyPathArg := filepath.Join(tmpDir, "key.pub")

			pubkeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			require.Nil(t, err)

			pubkeyPemBytes := pem.EncodeToMemory(
				&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pubkeyBytes,
				},
			)

			err = realOsExecutor.WriteFile(pubkeyPathArg, pubkeyPemBytes, 0644)
			require.Nil(t, err)

			fakeError := errors.New("encryptError")

			rsaSvc := rsa.NewRsaService(realOsExecutor)
			b64Svc := base64.NewBase64Service()

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)
			encContentSvc := &testContent.MockEncryptedContentService{}
			encContentSvc.On(
				"Encrypt",
				mock.AnythingOfType("*passphrase.Passphrase"),
				mock.AnythingOfType("*content.Content"),
			).Return(nil, fakeError)

			cmdInstance := NewEncryptCommand(realOsExecutor, rsaSvc, encPassphraseSvc, encContentSvc)

			cmdArgs := []string{
				fmt.Sprintf("--public-key-path=%s", pubkeyPathArg),
				fmt.Sprintf("--in=%s", inPathFlag),
				"--out=/tmp/example.out",
			}

			_, err = testutils.RunCommandInSameProcess(
				cmdInstance,
				cmdArgs,
				outputBuff,
			)

			assert.Contains(
				t,
				err.Error(),
				"failed to encrypt content using AES passphrase",
			)
		},
	)

	t.Run(
		"with 'public-key-path', 'in', 'out' flags specified, but encrypting passphrase fails, "+
			"it returns error",
		func(t *testing.T) {
			tmpDir := testutils.TestCwd(t, "vaulted")

			outputBuff := &bytes.Buffer{}
			realOsExecutor := &os.RealOsExecutor{}

			inPathFlag := filepath.Join(tmpDir, "in.raw")
			inFileContent := []byte("mysecret")
			err := realOsExecutor.WriteFile(inPathFlag, inFileContent, 0644)
			require.Nil(t, err)

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			pubkeyPathArg := filepath.Join(tmpDir, "key.pub")

			pubkeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			require.Nil(t, err)

			pubkeyPemBytes := pem.EncodeToMemory(
				&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pubkeyBytes,
				},
			)

			err = realOsExecutor.WriteFile(pubkeyPathArg, pubkeyPemBytes, 0644)
			require.Nil(t, err)

			rsaSvc := rsa.NewRsaService(realOsExecutor)
			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			passphrase := &passphrase.Passphrase{
				Content: []byte("1234567890123456"),
			}
			encPassphraseSvc := &testEncPassphraseService.MockEncryptedPassphraseService{}
			// NOTE: Mock this function w/ receiver too, since partial mocking is not possible
			// and it has to pass to actually test the next function.
			encPassphraseSvc.On(
				"GeneratePassphrase",
				16,
			).Return(passphrase, nil)

			fakeError := errors.New("encryptError")

			encPassphraseSvc.On(
				"Encrypt",
				mock.AnythingOfType("*rsa.PublicKey"),
				mock.AnythingOfType("*passphrase.Passphrase"),
			).Return(nil, fakeError)

			encContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)

			cmdInstance := NewEncryptCommand(realOsExecutor, rsaSvc, encPassphraseSvc, encContentSvc)

			cmdArgs := []string{
				fmt.Sprintf("--public-key-path=%s", pubkeyPathArg),
				fmt.Sprintf("--in=%s", inPathFlag),
				"--out=/tmp/example.out",
			}

			_, err = testutils.RunCommandInSameProcess(
				cmdInstance,
				cmdArgs,
				outputBuff,
			)

			assert.Contains(
				t,
				err.Error(),
				"failed to encrypt AES passphrase using RSA public key",
			)
		},
	)

	t.Run(
		"with 'public-key-path', 'in', 'out' flags specified, "+
			"but serializing encrypted passphrase fails, "+
			"it returns error",
		func(t *testing.T) {
			tmpDir := testutils.TestCwd(t, "vaulted")

			outputBuff := &bytes.Buffer{}
			realOsExecutor := &os.RealOsExecutor{}

			inPathFlag := filepath.Join(tmpDir, "in.raw")
			inFileContent := []byte("mysecret")
			err := realOsExecutor.WriteFile(inPathFlag, inFileContent, 0644)
			require.Nil(t, err)

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			pubkeyPathArg := filepath.Join(tmpDir, "key.pub")

			pubkeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			require.Nil(t, err)

			pubkeyPemBytes := pem.EncodeToMemory(
				&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pubkeyBytes,
				},
			)

			err = realOsExecutor.WriteFile(pubkeyPathArg, pubkeyPemBytes, 0644)
			require.Nil(t, err)

			rsaSvc := rsa.NewRsaService(realOsExecutor)
			b64Svc := base64.NewBase64Service()
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			passphraseArg := &passphrase.Passphrase{
				Content: []byte("1234567890123456"),
			}
			encPassphraseSvc := &testEncPassphraseService.MockEncryptedPassphraseService{}
			// NOTE: Mock this function w/ receiver too, since partial mocking is not possible
			// and it has to pass to actually test the next function.
			encPassphraseSvc.On(
				"GeneratePassphrase",
				16,
			).Return(passphraseArg, nil)

			encryptedPassphrase := passphrase.NewEncryptedPassphrase([]byte("1a2b3c4d"))
			encPassphraseSvc.On(
				"Encrypt",
				mock.AnythingOfType("*rsa.PublicKey"),
				mock.AnythingOfType("*passphrase.Passphrase"),
			).Return(encryptedPassphrase, nil)

			fakeError := errors.New("serializeError")
			encPassphraseSvc.On(
				"Serialize",
				encryptedPassphrase,
			).Return(nil, fakeError)

			encContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)

			cmdInstance := NewEncryptCommand(realOsExecutor, rsaSvc, encPassphraseSvc, encContentSvc)

			cmdArgs := []string{
				fmt.Sprintf("--public-key-path=%s", pubkeyPathArg),
				fmt.Sprintf("--in=%s", inPathFlag),
				"--out=/tmp/example.out",
			}

			_, err = testutils.RunCommandInSameProcess(
				cmdInstance,
				cmdArgs,
				outputBuff,
			)

			assert.Contains(
				t,
				err.Error(),
				"failed to base64 serialize encrypted passphrase",
			)
		},
	)

	t.Run(
		"with 'public-key-path', 'in', 'out' flags specified, "+
			"but serializing encrypted content fails, "+
			"it returns error",
		func(t *testing.T) {
			tmpDir := testutils.TestCwd(t, "vaulted")

			outputBuff := &bytes.Buffer{}
			realOsExecutor := &os.RealOsExecutor{}

			inPathFlag := filepath.Join(tmpDir, "in.raw")
			inFileContent := []byte("mysecret")
			err := realOsExecutor.WriteFile(inPathFlag, inFileContent, 0644)
			require.Nil(t, err)

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			pubkeyPathArg := filepath.Join(tmpDir, "key.pub")

			pubkeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			require.Nil(t, err)

			pubkeyPemBytes := pem.EncodeToMemory(
				&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pubkeyBytes,
				},
			)

			err = realOsExecutor.WriteFile(pubkeyPathArg, pubkeyPemBytes, 0644)
			require.Nil(t, err)

			rsaSvc := rsa.NewRsaService(realOsExecutor)
			b64Svc := base64.NewBase64Service()

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)
			encContentSvc := &testContent.MockEncryptedContentService{}

			encryptedContent := content.NewEncryptedContent([]byte("1a2b3c4d"))
			encContentSvc.On(
				"Encrypt",
				mock.AnythingOfType("*passphrase.Passphrase"),
				mock.AnythingOfType("*content.Content"),
			).Return(encryptedContent, nil)

			fakeError := errors.New("serializeError")
			encContentSvc.On(
				"Serialize",
				encryptedContent,
			).Return(nil, fakeError)

			cmdInstance := NewEncryptCommand(realOsExecutor, rsaSvc, encPassphraseSvc, encContentSvc)

			cmdArgs := []string{
				fmt.Sprintf("--public-key-path=%s", pubkeyPathArg),
				fmt.Sprintf("--in=%s", inPathFlag),
				"--out=/tmp/example.out",
			}

			_, err = testutils.RunCommandInSameProcess(
				cmdInstance,
				cmdArgs,
				outputBuff,
			)

			assert.Contains(
				t,
				err.Error(),
				"failed to base64 serialize encrypted content",
			)
		},
	)

	t.Run(
		"with 'public-key-path', 'in', 'out' flags specified, "+
			"but writing the encrypted content at 'out' path fails, "+
			"it returns error",
		func(t *testing.T) {
			tmpDir := testutils.TestCwd(t, "vaulted")

			outputBuff := &bytes.Buffer{}
			realOsExecutor := &os.RealOsExecutor{}

			inPathFlag := filepath.Join(tmpDir, "in.raw")
			inFileContent := []byte("mysecret")

			err := realOsExecutor.WriteFile(inPathFlag, inFileContent, 0644)
			require.Nil(t, err)

			outPathFlag := "/tmp/example.out"

			fakeError := errors.New("writeFileError")
			osExecutor := ostest.NewFakeOsExecutor(t)
			// NOTE: Mock this function w/ receiver too, since partial mocking is not possible
			// and it has to pass to actually test the next function.
			osExecutor.On(
				"ReadFile",
				inPathFlag,
			).Return(inFileContent, nil)

			osExecutor.On("Stdout").Return(outputBuff)

			osExecutor.On(
				"WriteFile",
				outPathFlag,
				mock.AnythingOfType("[]uint8"),
				mock.AnythingOfType("FileMode"),
			).Return(fakeError)

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			pubkeyPathArg := filepath.Join(tmpDir, "key.pub")

			pubkeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			require.Nil(t, err)

			pubkeyPemBytes := pem.EncodeToMemory(
				&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pubkeyBytes,
				},
			)

			err = realOsExecutor.WriteFile(pubkeyPathArg, pubkeyPemBytes, 0644)
			require.Nil(t, err)

			rsaSvc := rsa.NewRsaService(realOsExecutor)
			b64Svc := base64.NewBase64Service()

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())
			encContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)

			cmdInstance := NewEncryptCommand(osExecutor, rsaSvc, encPassphraseSvc, encContentSvc)

			cmdArgs := []string{
				fmt.Sprintf("--public-key-path=%s", pubkeyPathArg),
				fmt.Sprintf("--in=%s", inPathFlag),
				fmt.Sprintf("--out=%s", outPathFlag),
			}

			_, err = testutils.RunCommandInSameProcess(
				cmdInstance,
				cmdArgs,
				outputBuff,
			)

			assert.Contains(
				t,
				err.Error(),
				"failed to write encrypted content at out file path",
			)
		},
	)

	t.Run(
		"with 'public-key-path', 'in', 'out' flags specified "+
			"it prints encrypted passphrase in stdout and "+
			"writes encrypted content at 'out' file path",
		func(t *testing.T) {
			tmpDir := testutils.TestCwd(t, "vaulted")

			outputBuff := &bytes.Buffer{}
			realOsExecutor := &os.RealOsExecutor{}

			inPathFlag := filepath.Join(tmpDir, "in.raw")
			inFileContent := []byte("mysecret")

			err := realOsExecutor.WriteFile(inPathFlag, inFileContent, 0644)
			require.Nil(t, err)

			privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
			require.Nil(t, err)

			pubkeyPathArg := filepath.Join(tmpDir, "key.pub")

			pubkeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			require.Nil(t, err)

			pubkeyPemBytes := pem.EncodeToMemory(
				&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pubkeyBytes,
				},
			)

			err = realOsExecutor.WriteFile(pubkeyPathArg, pubkeyPemBytes, 0644)
			require.Nil(t, err)

			rsaSvc := rsa.NewRsaService(realOsExecutor)
			b64Svc := base64.NewBase64Service()

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())
			encContentSvc := content.NewLegacyEncryptedContentService(b64Svc, aesSvc)

			outPathFlag := filepath.Join(tmpDir, "out.enc")
			cmdInstance := NewEncryptCommand(realOsExecutor, rsaSvc, encPassphraseSvc, encContentSvc)

			cmdArgs := []string{
				fmt.Sprintf("--public-key-path=%s", pubkeyPathArg),
				fmt.Sprintf("--in=%s", inPathFlag),
				fmt.Sprintf("--out=%s", outPathFlag),
			}

			_, err = testutils.RunCommandInSameProcess(
				cmdInstance,
				cmdArgs,
				outputBuff,
			)

			assert.Nil(t, err)
		},
	)
}
