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
	"github.com/sumup-oss/vaulted/version"
)

func TestNewVersionCmd(t *testing.T) {
	t.Parallel()

	osExecutor := ostest.NewFakeOsExecutor(t)
	actual := NewVersionCmd(osExecutor)

	assert.Equal(t, "version", actual.Use)
	assert.Equal(t, "Print the version of vaulted", actual.Short)
	assert.Equal(t, "Print the version of vaulted.", actual.Long)
}

func TestVersionCmd_Execute(t *testing.T) {
	t.Parallel()

	outputBuff := &bytes.Buffer{}

	osExecutor := ostest.NewFakeOsExecutor(t)
	osExecutor.On("Stdout").Return(outputBuff)

	_, err := testutils.RunCommandInSameProcess(
		NewVersionCmd(osExecutor),
		[]string{},
		outputBuff,
	)
	assert.Equal(t, version.Version, outputBuff.String())
	assert.Nil(t, err)

	osExecutor.AssertExpectations(t)
}
