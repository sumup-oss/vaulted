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

package test

import (
	"io"

	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/stretchr/testify/mock"

	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/terraform"
)

type MockTerraformSvc struct {
	mock.Mock
}

func (m *MockTerraformSvc) TerraformContentToHCLfile(
	hclParser hcl.Parser,
	terraformContent *terraform.Content,
) (*ast.File, error) {
	args := m.Called(hclParser, terraformContent)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*ast.File), nil
}

func (m *MockTerraformSvc) WriteHCLfile(hclPrinter hcl.Printer, hclFile *ast.File, output io.Writer) error {
	args := m.Called(hclPrinter, hclFile, output)
	return args.Error(0)
}

func (m *MockTerraformSvc) TerraformResourceToHCLfile(
	hclParser hcl.Parser,
	resource terraform.Resource,
) (*ast.File, error) {
	args := m.Called(hclParser, resource)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*ast.File), nil
}

func (m *MockTerraformSvc) ModifyInPlaceHclAst(
	hclParser hcl.Parser,
	hclBytes []byte,
	objectItemVisitorFunc func(item *ast.ObjectItem) error,
) (*ast.File, error) {
	args := m.Called(hclParser, hclBytes, objectItemVisitorFunc)
	returnValue := args.Get(0)
	err := args.Error(1)

	if returnValue == nil {
		return nil, err
	}

	return returnValue.(*ast.File), nil
}
