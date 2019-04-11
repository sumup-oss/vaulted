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
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/sumup-oss/go-pkgs/os/ostest"
	"github.com/sumup-oss/go-pkgs/testutils"
	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/rsa"
)

func TestNewRootCmd(t *testing.T) {
	t.Parallel()

	osExecutor := ostest.NewFakeOsExecutor(t)
	rsaSvc := rsa.NewRsaService(osExecutor)
	aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())
	base64Svc := base64.NewBase64Service()
	hclSvc := hcl.NewHclService()
	actual := NewRootCmd(osExecutor, rsaSvc, aesSvc, base64Svc, hclSvc)

	assert.Equal(t, true, actual.SilenceUsage)
	assert.Equal(t, true, actual.SilenceErrors)
	assert.Equal(t, "vaulted", actual.Use)
	assert.Equal(t, "Vault encrypt/decrypt cli utility", actual.Short)
	assert.Equal(t, "Vault encrypt/decrypt using asymmetric RSA keys and AES", actual.Long)
}

func TestRootCmd_Execute(t *testing.T) {
	t.Parallel()

	outputBuff := &bytes.Buffer{}

	osExecutor := ostest.NewFakeOsExecutor(t)
	osExecutor.On("Stdout").Return(outputBuff)

	rsaSvc := rsa.NewRsaService(osExecutor)
	aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())
	base64Svc := base64.NewBase64Service()
	hclSvc := hcl.NewHclService()
	cmdInstance := NewRootCmd(osExecutor, rsaSvc, aesSvc, base64Svc, hclSvc)

	_, err := testutils.RunCommandInSameProcess(
		cmdInstance,
		[]string{},
		outputBuff,
	)

	assert.Equal(t, "Use `--help` to see available commands", outputBuff.String())
	assert.Nil(t, err)

	osExecutor.AssertExpectations(t)
}
