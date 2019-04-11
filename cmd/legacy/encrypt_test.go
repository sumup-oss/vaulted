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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/sumup-oss/go-pkgs/os/ostest"
	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/rsa"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
)

func TestNewEncryptCommand(t *testing.T) {
	t.Parallel()

	osExecutor := ostest.NewFakeOsExecutor(t)
	rsaSvc := rsa.NewRsaService(osExecutor)
	b64Svc := base64.NewBase64Service()
	aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

	encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)
	encContentSvc := content.NewV1EncryptedContentService(b64Svc, aesSvc)

	actual := NewEncryptCommand(osExecutor, rsaSvc, encPassphraseSvc, encContentSvc)

	assert.Equal(
		t,
		"encrypt --public-key-path ./my-pubkey.pem --in ./mysecret.txt --out ./mysecret-enc.base64",
		actual.Use,
	)

	assert.Equal(
		t,
		"Encrypt a file/value",
		actual.Short,
	)

	assert.Equal(
		t,
		"Encrypt a file/value using AES128-CBC symmetric encryption. "+
			"Passfile runtime random generated and encrypted with RSA asymmetric keypair.",
		actual.Long,
	)

	publicKeyPathFlag := actual.Flag("public-key-path")

	assert.NotNil(t, publicKeyPathFlag)
	assert.Equal(
		t,
		"Path to RSA public key used to encrypt runtime random generated passphrase.",
		publicKeyPathFlag.Usage,
	)

	inPathFlag := actual.Flag("in")

	assert.NotNil(t, inPathFlag)
	assert.Equal(t, "Path to the input file.", inPathFlag.Usage)

	outPathFlag := actual.Flag("out")

	assert.NotNil(t, outPathFlag)
	assert.Equal(
		t,
		"Path to the output file, that's going to be encrypted and encoded in base64.",
		outPathFlag.Usage,
	)
}
