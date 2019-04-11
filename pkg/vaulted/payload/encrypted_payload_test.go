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
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
)

func TestNewEncryptedPayload(t *testing.T) {
	t.Run(
		"it creates encrypted payload with specified 'header', 'encrypted passphrase' and 'encrypted content'",
		func(t *testing.T) {
			t.Parallel()

			h := header.NewHeader()
			encPassphrase := passphrase.NewEncryptedPassphrase([]byte("1a2b3c4f"))
			encContent := content.NewEncryptedContent([]byte("1a2b3c4f"))

			actual := NewEncryptedPayload(h, encPassphrase, encContent)

			assert.Equal(t, h, actual.Header)
			assert.Equal(t, encPassphrase, actual.EncryptedPassphrase)
			assert.Equal(t, encContent, actual.EncryptedContent)
		},
	)
}
