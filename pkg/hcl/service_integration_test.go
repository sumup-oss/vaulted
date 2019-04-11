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
	"bytes"
	"errors"
	"testing"

	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type fakeWriter struct {
	mock.Mock
}

func (f *fakeWriter) Write(p []byte) (n int, err error) {
	args := f.Called(p)
	return args.Int(0), args.Error(1)
}

func TestHclService_Parse(t *testing.T) {
	t.Run(
		"with `src` that is not JSON or HCL, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			svc := NewHclService()
			srcArg := []byte("not json")

			actualReturn, actualErr := svc.Parse(srcArg)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"key 'not json' expected start of object ('{') or assignment ('='",
			)
		},
	)

	t.Run(
		"with `src` that is invalid (not properly closed) JSON, it actually parses the JSON and returns AST",
		func(t *testing.T) {
			t.Parallel()

			svc := NewHclService()
			// NOTE: Invalid due to not closed object
			srcArg := []byte(`{ "a": "b"`)

			actualReturn, actualErr := svc.Parse(srcArg)
			require.Nil(t, actualErr)

			node := actualReturn.Node.(*ast.ObjectList)
			assert.Equal(t, 1, len(node.Items))
			object := node.Items[0]

			assert.Equal(t, `"a"`, object.Keys[0].Token.Text)
			objectValue := object.Val.(*ast.LiteralType)
			assert.Equal(t, `"b"`, objectValue.Token.Text)
		},
	)

	t.Run(
		"with marshaled `src` that is valid (properly closed and no comments) JSON, it returns ast file",
		func(t *testing.T) {
			t.Parallel()

			svc := NewHclService()
			srcArg := []byte(`{ "a": "b" }`)

			actualReturn, actualErr := svc.Parse(srcArg)
			require.Nil(t, actualErr)

			node := actualReturn.Node.(*ast.ObjectList)
			assert.Equal(t, 1, len(node.Items))
			object := node.Items[0]

			assert.Equal(t, `"a"`, object.Keys[0].Token.Text)
			objectValue := object.Val.(*ast.LiteralType)
			assert.Equal(t, `"b"`, objectValue.Token.Text)
		},
	)

	t.Run(
		"with marshaled `src` that is valid (properly closed and no comments) HCL, it returns ast file",
		func(t *testing.T) {
			t.Parallel()

			svc := NewHclService()
			srcArg := []byte(`"a" = "b"`)

			actualReturn, actualErr := svc.Parse(srcArg)
			require.Nil(t, actualErr)

			node := actualReturn.Node.(*ast.ObjectList)
			assert.Equal(t, 1, len(node.Items))
			object := node.Items[0]

			assert.Equal(t, 1, len(object.Keys))

			assert.Equal(t, `"a"`, object.Keys[0].Token.Text)
			objectValue := object.Val.(*ast.LiteralType)
			assert.Equal(t, `"b"`, objectValue.Token.Text)
		},
	)
}

func TestHclService_Fprint(t *testing.T) {
	t.Run(
		"with non-writable `output` and non-nil `node`, it returns an error",
		func(t *testing.T) {
			wrArg := &fakeWriter{}
			wrArg.Test(t)

			fakeError := errors.New("fakeWriteError")

			wrArg.On(
				"Write",
				mock.Anything,
			).Return(
				0,
				fakeError,
			)

			svc := NewHclService()

			nodeArg := &ast.ObjectKey{
				Token: token.Token{
					Type: token.STRING,
					Text: `"foo"`,
				},
			}

			actualErr := svc.Fprint(wrArg, nodeArg)

			assert.Equal(t, fakeError, actualErr)
			wrArg.AssertExpectations(t)
		},
	)

	t.Run(
		"with writable `output` and non-nil `node`, it writes the JSON representation of the AST in `output`",
		func(t *testing.T) {
			var wrArg bytes.Buffer

			svc := NewHclService()

			nodeArg := &ast.ObjectKey{
				Token: token.Token{
					Type: token.STRING,
					Text: `"foo"`,
				},
			}

			actualErr := svc.Fprint(&wrArg, nodeArg)
			require.Nil(t, actualErr)

			assert.Equal(t, `"foo"`, wrArg.String())
		},
	)

	t.Run(
		"with writable `output` and nil `node`, it doesn't write anything in `output`",
		func(t *testing.T) {
			var wrArg bytes.Buffer

			svc := NewHclService()

			beforeWriteLen := wrArg.Len()

			actualErr := svc.Fprint(&wrArg, nil)
			require.Nil(t, actualErr)

			assert.Equal(t, beforeWriteLen, wrArg.Len())
			assert.Equal(t, ``, wrArg.String())
		},
	)
}
