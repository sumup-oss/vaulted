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
	"bytes"
	"crypto/rand"
	stdRsa "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/sumup-oss/vaulted/pkg/vaulted"

	"github.com/sumup-oss/vaulted/pkg/testutils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sumup-oss/go-pkgs/os"
	"github.com/sumup-oss/go-pkgs/os/ostest"
	gopkgsTestUtils "github.com/sumup-oss/go-pkgs/testutils"
	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/rsa"
)

func TestNewResourceCmd_Execute(t *testing.T) {
	t.Run(
		"with no arguments, it returns error",
		func(t *testing.T) {
			t.Parallel()

			outputBuff := &bytes.Buffer{}

			osExecutor := ostest.NewFakeOsExecutor(t)

			b64Svc := base64.NewBase64Service()
			rsaSvc := rsa.NewRsaService(osExecutor)
			aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

			cmdInstance := NewNewResourceCommand(
				osExecutor,
				rsaSvc,
				b64Svc,
				aesSvc,
			)

			_, err := gopkgsTestUtils.RunCommandInSameProcess(
				cmdInstance,
				[]string{},
				outputBuff,
			)

			assert.Equal(
				t,
				`required flag(s) "path", "public-key-path", "resource-name" not set`,
				err.Error(),
			)
		},
	)

	t.Run(
		"with 'public-key-path', 'path', 'resource-name', 'in' and 'out' flags specified "+
			"it prints encrypted passphrase in stdout and "+
			"writes encrypted content at 'out' file path",
		func(t *testing.T) {
			tmpDir := gopkgsTestUtils.TestCwd(t, "vaulted")

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

			outPathFlag := filepath.Join(tmpDir, "out.tf")
			cmdInstance := NewNewResourceCommand(
				realOsExecutor,
				rsaSvc,
				b64Svc,
				aes.NewAesService(pkcs7.NewPkcs7Service()),
			)

			pathArg := "secret/exampleapp/example"
			resourceNameArg := "exampleapp"

			cmdArgs := []string{
				fmt.Sprintf("--public-key-path=%s", pubkeyPathArg),
				fmt.Sprintf("--in=%s", inPathFlag),
				fmt.Sprintf("--out=%s", outPathFlag),
				fmt.Sprintf("--path=%s", pathArg),
				fmt.Sprintf("--resource-name=%s", resourceNameArg),
			}

			_, err = gopkgsTestUtils.RunCommandInSameProcess(
				cmdInstance,
				cmdArgs,
				outputBuff,
			)
			require.Nil(t, err)
			assert.Equal(t, "", outputBuff.String())

			outContent, err := realOsExecutor.ReadFile(outPathFlag)
			require.Nil(t, err)

			regexMatches := testutils.NewTerraformRegex.FindAllStringSubmatch(string(outContent), -1)
			require.Equal(t, 1, len(regexMatches))

			resourcePrefix := vaulted.SanitizeFilename(outPathFlag)
			fullResourceName := fmt.Sprintf("%s_%s", resourcePrefix, resourceNameArg)

			resource := regexMatches[0]
			assert.Equal(t, fullResourceName, resource[1])
			assert.Equal(t, pathArg, resource[2])
			// NOTE: Encrypted payload is not empty
			assert.NotEqual(t, "", resource[3])
		},
	)
}
