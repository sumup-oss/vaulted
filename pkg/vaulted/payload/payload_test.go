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

package payload

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sumup-oss/go-pkgs/os/ostest"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/rsa"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
)

func TestNewPayload(t *testing.T) {
	t.Run(
		"it creates a new payload with specified 'header', 'passphrase' and 'content'",
		func(t *testing.T) {
			headerArg := header.NewHeader()

			encPassphraseSvc := passphrase.NewEncryptedPassphraseService(
				base64.NewBase64Service(),
				rsa.NewRsaService(
					ostest.NewFakeOsExecutor(t),
				),
			)

			passphraseArg, err := encPassphraseSvc.GeneratePassphrase(16)
			contentArg := content.NewContent([]byte("12345678"))

			actual := NewPayload(headerArg, passphraseArg, contentArg)

			require.Nil(t, err)

			assert.Equal(t, headerArg, actual.Header)
			assert.Equal(t, passphraseArg, actual.Passphrase)
			assert.Equal(t, contentArg, actual.Content)
		},
	)
}
