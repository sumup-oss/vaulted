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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/sumup-oss/go-pkgs/os/ostest"
	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/rsa"
)

func TestNewNewResourceCmd(t *testing.T) {
	t.Parallel()

	osExecutor := ostest.NewFakeOsExecutor(t)
	b64Svc := base64.NewBase64Service()
	rsaSvc := rsa.NewRsaService(osExecutor)
	aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

	actual := NewNewResourceCommand(osExecutor, rsaSvc, b64Svc, aesSvc)

	assert.Equal(
		t,
		"new-resource --public-key-path ./my-pubkey.pem "+
			"--in ./mysecret.txt "+
			"--out ./mysecret.tf "+
			"--path secret/example-app/example-key "+
			"--resource-name example_app_example_key",
		actual.Use,
	)
	assert.Equal(
		t,
		"Create new terraform vaulted vault secret resource",
		actual.Short,
	)
	assert.Equal(
		t,
		"Create new terraform vaulted vault secret resource",
		actual.Long,
	)
}
