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

package terraform

import (
	"bytes"
	"errors"
	"testing"

	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/hcl/test"
)

func TestService_WriteHCLfile(t *testing.T) {
	t.Run(
		"when writing at 'output' fails, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			fakeError := errors.New("fakeCreateError")

			hclPrinterArg := &test.MockHclPrinter{}
			hclPrinterArg.Test(t)

			var fakeOutput bytes.Buffer
			hclSvc := hcl.NewHclService()

			hclFileArg, err := hclSvc.Parse([]byte(`{ "a": "b" }`))
			require.Nil(t, err)

			hclPrinterArg.On(
				"Fprint",
				&fakeOutput,
				hclFileArg,
			).Return(fakeError)

			svc := NewTerraformService()
			actualErr := svc.WriteHCLfile(
				hclPrinterArg,
				hclFileArg,
				&fakeOutput,
			)

			hclPrinterArg.AssertExpectations(t)
			require.NotNil(t, actualErr)

			assert.Contains(t, actualErr.Error(), fakeError.Error())
		},
	)

	t.Run(
		"when `hclPrinter` successfully writes to `output`, it writes HCL",
		func(t *testing.T) {
			t.Parallel()

			hclSvc := hcl.NewHclService()
			hclFileArg, err := hclSvc.Parse([]byte(`{ "a": "b" }`))
			require.Nil(t, err)

			var fakeOutput bytes.Buffer

			svc := NewTerraformService()
			actualErr := svc.WriteHCLfile(
				hclSvc,
				hclFileArg,
				&fakeOutput,
			)
			require.Nil(t, actualErr)

			assert.Equal(t, `"a" = "b"`, fakeOutput.String())
		},
	)
}

func TestService_TerraformContentToHCLfile(t *testing.T) {
	t.Run(
		"when `terrraformContent` has no resources, it returns empty AST file",
		func(t *testing.T) {
			t.Parallel()

			hclParserArg := hcl.NewHclService()
			terraformContentArg := NewTerraformContent()

			svc := NewTerraformService()

			actualReturn, actualErr := svc.TerraformContentToHCLfile(hclParserArg, terraformContentArg)

			require.Nil(t, actualErr)
			assert.Nil(t, actualReturn.Node)
		},
	)

	t.Run(
		"when `terrraformContent` has at least 1 resource, "+
			"but HCL parsing of prepared terraform resources map fails "+
			"it returns error",
		func(t *testing.T) {
			t.Parallel()

			fakeError := errors.New("")
			hclParserArg := &test.MockHclParser{}
			hclParserArg.On(
				"Parse",
				mock.AnythingOfType("[]uint8"),
			).Return(nil, fakeError)

			terraformContentArg := NewTerraformContent()

			tfResource := NewTerraformResource(
				"example_resource",
				"vault_encrypted_secret",
			)
			tfResource.Content["foo"] = "bar"

			terraformContentArg.AddResource(tfResource)

			svc := NewTerraformService()

			actualReturn, actualErr := svc.TerraformContentToHCLfile(hclParserArg, terraformContentArg)

			require.Nil(t, actualReturn)
			assert.Contains(
				t,
				actualErr.Error(),
				"failed to parse JSON marshaled terraform content as HCL",
			)
		},
	)

	t.Run(
		"when `terrraformContent` has at least 1 resource, "+
			"and HCL parsing of marshaled to JSON resources succeeds"+
			"it returns AST file with resource",
		func(t *testing.T) {
			t.Parallel()

			hclParserArg := hcl.NewHclService()
			terraformContentArg := NewTerraformContent()

			tfResource := NewTerraformResource(
				"example_resource",
				"vault_encrypted_secret",
			)
			tfResource.Content["foo"] = "bar"

			terraformContentArg.AddResource(tfResource)

			svc := NewTerraformService()

			actualReturn, actualErr := svc.TerraformContentToHCLfile(hclParserArg, terraformContentArg)

			require.Nil(t, actualErr)
			astNode := actualReturn.Node.(*ast.ObjectList)

			assert.Equal(t, 1, len(astNode.Items))

			astResourceItem := astNode.Items[0]

			assert.Equal(t, 3, len(astResourceItem.Keys))

			assert.Equal(t, token.STRING, astResourceItem.Keys[0].Token.Type)
			assert.Equal(t, `"resource"`, astResourceItem.Keys[0].Token.Text)

			assert.Equal(t, token.STRING, astResourceItem.Keys[1].Token.Type)
			assert.Equal(t, `"vault_encrypted_secret"`, astResourceItem.Keys[1].Token.Text)

			assert.Equal(t, token.STRING, astResourceItem.Keys[2].Token.Type)
			assert.Equal(t, `"example_resource"`, astResourceItem.Keys[2].Token.Text)

			astResourceObject := astResourceItem.Val.(*ast.ObjectType)
			assert.Equal(t, 1, len(astResourceObject.List.Items))

			astResourceObjectItemsKeys := astResourceObject.List.Items[0].Keys
			assert.Equal(t, 1, len(astResourceObjectItemsKeys))
			assert.Equal(t, `"foo"`, astResourceObjectItemsKeys[0].Token.Text)
			assert.Equal(t, token.STRING, astResourceObjectItemsKeys[0].Token.Type)

			astResourceObjectItemValue := astResourceObject.List.Items[0].Val.(*ast.LiteralType)

			assert.Equal(t, `"bar"`, astResourceObjectItemValue.Token.Text)
			assert.Equal(t, token.STRING, astResourceObjectItemValue.Token.Type)
		},
	)
}

func TestService_TerraformResourceToHCLfile(t *testing.T) {
	t.Run(
		"when `resource` has empty 'name', it returns error",
		func(t *testing.T) {
			t.Parallel()

			hclParserArg := hcl.NewHclService()

			svc := NewTerraformService()

			tfResource := NewTerraformResource(
				"",
				"vault_encrypted_secret",
			)
			actualReturn, actualErr := svc.TerraformResourceToHCLfile(hclParserArg, tfResource)

			require.Nil(t, actualReturn)
			assert.Equal(t, errResourceWithEmptyName, actualErr)
		},
	)

	t.Run(
		"when `resource` has empty 'type', it returns error",
		func(t *testing.T) {
			t.Parallel()

			hclParserArg := hcl.NewHclService()

			svc := NewTerraformService()

			tfResource := NewTerraformResource(
				"example",
				"",
			)
			actualReturn, actualErr := svc.TerraformResourceToHCLfile(hclParserArg, tfResource)

			require.Nil(t, actualReturn)
			assert.Equal(t, errResourceWithEmptyType, actualErr)
		},
	)

	t.Run(
		"when `resource` has present 'type' and 'name' fields, "+
			"but HCL parsing of prepared terraform resources map fails "+
			"it returns error",
		func(t *testing.T) {
			t.Parallel()

			fakeError := errors.New("")
			hclParserArg := &test.MockHclParser{}
			hclParserArg.On(
				"Parse",
				mock.AnythingOfType("[]uint8"),
			).Return(nil, fakeError)

			tfResource := NewTerraformResource(
				"example_resource",
				"vault_encrypted_secret",
			)
			tfResource.Content["foo"] = "bar"

			svc := NewTerraformService()

			actualReturn, actualErr := svc.TerraformResourceToHCLfile(hclParserArg, tfResource)

			require.Nil(t, actualReturn)
			assert.Contains(
				t,
				actualErr.Error(),
				"failed to parse JSON marshaled terraform content as HCL",
			)
		},
	)

	t.Run(
		"when `resource` has present 'name' and 'type', "+
			"and HCL parsing of marshaled to JSON resources succeeds"+
			"it returns AST file with resource",
		func(t *testing.T) {
			t.Parallel()

			hclParserArg := hcl.NewHclService()
			tfResource := NewTerraformResource(
				"example_resource",
				"vault_encrypted_secret",
			)
			tfResource.Content["foo"] = "bar"

			svc := NewTerraformService()

			actualReturn, actualErr := svc.TerraformResourceToHCLfile(hclParserArg, tfResource)

			require.Nil(t, actualErr)
			astNode := actualReturn.Node.(*ast.ObjectList)

			assert.Equal(t, 1, len(astNode.Items))

			astResourceItem := astNode.Items[0]

			assert.Equal(t, 3, len(astResourceItem.Keys))

			assert.Equal(t, token.STRING, astResourceItem.Keys[0].Token.Type)
			assert.Equal(t, `"resource"`, astResourceItem.Keys[0].Token.Text)

			assert.Equal(t, token.STRING, astResourceItem.Keys[1].Token.Type)
			assert.Equal(t, `"vault_encrypted_secret"`, astResourceItem.Keys[1].Token.Text)

			assert.Equal(t, token.STRING, astResourceItem.Keys[2].Token.Type)
			assert.Equal(t, `"example_resource"`, astResourceItem.Keys[2].Token.Text)

			astResourceObject := astResourceItem.Val.(*ast.ObjectType)
			assert.Equal(t, 1, len(astResourceObject.List.Items))

			astResourceObjectItemsKeys := astResourceObject.List.Items[0].Keys
			assert.Equal(t, 1, len(astResourceObjectItemsKeys))
			assert.Equal(t, `"foo"`, astResourceObjectItemsKeys[0].Token.Text)
			assert.Equal(t, token.STRING, astResourceObjectItemsKeys[0].Token.Type)

			astResourceObjectItemValue := astResourceObject.List.Items[0].Val.(*ast.LiteralType)

			assert.Equal(t, `"bar"`, astResourceObjectItemValue.Token.Text)
			assert.Equal(t, token.STRING, astResourceObjectItemValue.Token.Type)
		},
	)
}
