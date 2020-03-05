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
	"encoding/json"
	"errors"
	"io"

	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/palantir/stacktrace"

	"github.com/sumup-oss/vaulted/pkg/hcl"
)

var (
	errResourceWithEmptyName = errors.New("invalid terraform resource with empty name")
	errResourceWithEmptyType = errors.New("invalid terraform resource with empty type")
)

type Service struct{}

func NewTerraformService() *Service {
	return &Service{}
}

func (s *Service) WriteHCLfile(hclPrinter hcl.Printer, hclFile *ast.File, output io.Writer) error {
	err := hclPrinter.Fprint(output, hclFile)
	if err != nil {
		return stacktrace.Propagate(
			err,
			"failed to write HCL to file",
		)
	}

	return nil
}

func (s *Service) TerraformContentToHCLfile(hclParser hcl.Parser, terraformContent *Content) (*ast.File, error) {
	// NOTE: Nothing to write, return early
	if len(terraformContent.ResourcesByName) < 1 {
		return &ast.File{}, nil
	}
	// NOTE: Map of "HCL type", "HCL type name", "HCL resource name", "HCL resource key", "HCL resource value".
	terraformMap := map[string]map[string]map[string]map[string]string{}
	terraformMap["resource"] = map[string]map[string]map[string]string{}

	for _, resource := range terraformContent.ResourcesByName {
		terraformMap["resource"][resource.Type] = map[string]map[string]string{}
	}

	for resourceName, resource := range terraformContent.ResourcesByName {
		terraformMap["resource"][resource.Type][resourceName] = resource.Content
	}

	terraformMapBytes, err := json.Marshal(terraformMap)
	if err != nil {
		return nil, stacktrace.Propagate(
			err,
			"failed to marshal in JSON terraform content",
		)
	}

	hclAST, err := hclParser.Parse(terraformMapBytes)
	if err != nil {
		return nil, stacktrace.Propagate(
			err,
			"failed to parse JSON marshaled terraform content as HCL",
		)
	}

	return hclAST, nil
}

func (s *Service) TerraformResourceToHCLfile(hclParser hcl.Parser, resource Resource) (*ast.File, error) {
	if resource.Name == "" {
		return nil, errResourceWithEmptyName
	}

	if resource.Type == "" {
		return nil, errResourceWithEmptyType
	}

	resourceContentByName := map[string]map[string]string{}

	resourceContentByName[resource.Name] = resource.Content

	// NOTE: Map of "HCL type", "HCL type name", "HCL resource name", "HCL resource key", "HCL resource value".
	terraformMap := map[string]map[string]map[string]map[string]string{}
	terraformMap["resource"] = map[string]map[string]map[string]string{
		resource.Type: resourceContentByName,
	}

	terraformMapBytes, err := json.Marshal(terraformMap)
	if err != nil {
		return nil, stacktrace.Propagate(
			err,
			"failed to marshal in JSON terraform content",
		)
	}

	hclAST, err := hclParser.Parse(terraformMapBytes)
	if err != nil {
		return nil, stacktrace.Propagate(
			err,
			"failed to parse JSON marshaled terraform content as HCL",
		)
	}

	return hclAST, nil
}

func (s *Service) ModifyInPlaceHclAst(
	hclParser hcl.Parser,
	hclBytes []byte,
	objectItemVisitorFunc func(item *ast.ObjectItem) error,
) (*ast.File, error) {
	hclAst, err := hclParser.Parse(hclBytes)
	if err != nil {
		return nil, stacktrace.Propagate(
			err,
			"failed to parse HCL payload",
		)
	}

	fileObjectList, ok := hclAst.Node.(*ast.ObjectList)
	if !ok {
		return nil, stacktrace.NewError("HCL file does not have a list of resources")
	}

	for _, item := range fileObjectList.Items {
		err = objectItemVisitorFunc(item)
		if err != nil {
			return nil, err
		}
	}

	return hclAst, nil
}
