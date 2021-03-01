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

package hcl

import (
	"testing"

	"github.com/palantir/stacktrace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHclService_Parse(t *testing.T) {
	t.Run(
		"with `src` that is not HCL, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			svc := NewHclService()
			srcArg := []byte("not hcl")

			actualReturn, actualErr := svc.Parse(srcArg)
			require.Nil(t, actualReturn)
			require.NotNil(t, actualErr)

			require.IsType(t, stacktrace.RootCause(actualErr), &ParseErr{})
			parseErr := stacktrace.RootCause(actualErr).(*ParseErr)

			require.Equal(t, 1, len(parseErr.Errs))
			assert.Contains(
				t,
				parseErr.Errs[0].Error(),
				"Either a quoted string block label or an opening brace (\"{\") is expected here.",
			)
		},
	)

	t.Run(
		"with marshaled `src` that is valid (properly closed and no comments) HCL, it returns ast file",
		func(t *testing.T) {
			t.Parallel()

			svc := NewHclService()
			srcArg := []byte(`foo = "example"`)

			actualReturn, actualErr := svc.Parse(srcArg)
			require.Nil(t, actualErr)

			attrs := actualReturn.Body().Attributes()
			require.Equal(t, 1, len(attrs))
			require.NotNil(t, attrs["foo"])
			attr := attrs["foo"]

			require.Equal(t, `foo = "example"`, string(attr.BuildTokens(nil).Bytes()))

			blocks := actualReturn.Body().Blocks()
			require.Equal(t, 0, len(blocks))
		},
	)
}
