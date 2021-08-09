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

package header

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHeaderConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "$VED", DefaultName)
	assert.Equal(t, "1.0", DefaultVersion)
}

func TestNewHeader(t *testing.T) {
	t.Run(
		"it creates new header with default name and version",
		func(t *testing.T) {
			t.Parallel()

			header := NewHeader()

			assert.Equal(t, header.Name, DefaultName)
			assert.Equal(t, header.Version, DefaultVersion)
		},
	)
}

func TestHeader_Name(t *testing.T) {
	t.Run(
		"it returns header's 'name",
		func(t *testing.T) {
			t.Parallel()

			header := &Header{
				Name: "example",
			}

			assert.Equal(t, header.Name, "example")
		},
	)
}

func TestHeader_Version(t *testing.T) {
	t.Run(
		"it returns header's 'version",
		func(t *testing.T) {
			t.Parallel()

			header := &Header{
				Version: "example",
			}

			assert.Equal(t, header.Version, "example")
		},
	)
}
