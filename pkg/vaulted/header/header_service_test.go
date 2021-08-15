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
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestHeaderServiceConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, headerPartSeparator, ";")

	expectedAllowedNames := []string{DefaultName}

	assert.Equal(t, len(expectedAllowedNames), len(headerAllowedNames))
	assert.Equal(t, expectedAllowedNames[0], headerAllowedNames[0])

	expectedAllowedVersions := []string{DefaultVersion}

	assert.Equal(t, len(expectedAllowedVersions), len(headerAllowedVersions))
	assert.Equal(t, expectedAllowedVersions[0], headerAllowedVersions[0])

	assert.Equal(t, errHeadersPartsMismatch.Error(), "did not find exactly 2 header parts")
	assert.Equal(
		t,
		errHeaderNameInvalid.Error(),
		fmt.Sprintf(
			"did not find name equal to any of allowed header names: %#v",
			expectedAllowedNames,
		),
	)
	assert.Equal(
		t,
		errHeaderVersionInvalid.Error(),
		fmt.Sprintf(
			"did not find version equal to any of allowed header versions: %#v",
			expectedAllowedVersions,
		),
	)

	assert.Equal(
		t,
		errSerializeBlankHeaderName.Error(),
		"failed to serialize blank header name",
	)

	assert.Equal(
		t,
		errSerializeBlankHeaderVersion.Error(),
		"failed to serialize blank header version",
	)
}

func TestHeaderService_Serialize(t *testing.T) {
	t.Run(
		"with blank 'header's 'name', it returns error",
		func(t *testing.T) {
			t.Parallel()

			headerArg := &Header{
				Name:    "",
				Version: DefaultVersion,
			}

			headerSvc := NewHeaderService()

			actualReturn, actualErr := headerSvc.Serialize(headerArg)

			require.Nil(t, actualReturn)

			assert.Equal(t, errSerializeBlankHeaderName, actualErr)
		},
	)

	t.Run(
		"with blank 'header's 'version', it returns error",
		func(t *testing.T) {
			t.Parallel()

			headerArg := &Header{
				Name:    DefaultName,
				Version: "",
			}

			headerSvc := NewHeaderService()

			actualReturn, actualErr := headerSvc.Serialize(headerArg)

			require.Nil(t, actualReturn)

			assert.Equal(t, errSerializeBlankHeaderVersion, actualErr)
		},
	)

	t.Run(
		"with present 'header's 'name' and 'header's 'version', it returns serialized header using separator",
		func(t *testing.T) {
			t.Parallel()

			headerArg := NewHeader()

			headerSvc := NewHeaderService()

			actualReturn, actualErr := headerSvc.Serialize(headerArg)

			require.Nil(t, actualErr)

			expectedReturn := []byte(
				strings.Join(
					[]string{
						headerArg.Name,
						headerArg.Version,
					},
					headerPartSeparator,
				),
			)
			assert.Equal(t, expectedReturn, actualReturn)
		},
	)
}

func TestHeaderService_Deserialize(t *testing.T) {
	t.Run(
		"with blank 'content' provided, it returns no header and an error",
		func(t *testing.T) {
			t.Parallel()

			contentArg := ""

			headerService := NewHeaderService()

			header, err := headerService.Deserialize(contentArg)

			require.Nil(t, header)

			assert.Equal(t, err, errHeadersPartsMismatch)
		},
	)

	t.Run(
		"with 'content' that contains only 'name' part, it returns no header and an error",
		func(t *testing.T) {
			t.Parallel()

			contentArg := DefaultName

			headerService := NewHeaderService()

			header, err := headerService.Deserialize(contentArg)

			require.Nil(t, header)

			assert.Equal(t, err, errHeadersPartsMismatch)
		},
	)

	t.Run(
		"with 'content' that contains 'name' that's not allowed and 'version' part, it returns no header and an error",
		func(t *testing.T) {
			t.Parallel()

			contentArg := fmt.Sprintf("%s%s%s", "BAD", headerPartSeparator, DefaultVersion)

			headerService := &HeaderService{}

			header, err := headerService.Deserialize(contentArg)

			require.Nil(t, header)

			assert.Equal(t, err, errHeaderNameInvalid)
		},
	)

	t.Run(
		"with 'content' that contains 'name' part and 'version' that's not allowed, it returns no header and an error",
		func(t *testing.T) {
			t.Parallel()

			contentArg := fmt.Sprintf("%s%s%s", DefaultName, headerPartSeparator, "BAD")

			headerService := &HeaderService{}

			header, err := headerService.Deserialize(contentArg)

			require.Nil(t, header)

			assert.Equal(t, err, errHeaderVersionInvalid)
		},
	)

	t.Run(
		"with 'content' that contains allowed 'name' and 'version' parts, it returns header and no error",
		func(t *testing.T) {
			t.Parallel()

			contentArg := fmt.Sprintf("%s%s%s", DefaultName, headerPartSeparator, DefaultVersion)

			headerService := &HeaderService{}

			header, err := headerService.Deserialize(contentArg)

			require.NotNil(t, header)
			require.Nil(t, err)

			assert.Equal(t, header.Name, DefaultName)
			assert.Equal(t, header.Version, DefaultVersion)
		},
	)
}
