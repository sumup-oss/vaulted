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
	"io"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/printer"
)

// Service is an ad-hoc abstraction
// used to cover-up HashiCorp's bad abstraction
// that is not dependency injectable.
type Service struct{}

func NewHclService() *Service {
	return &Service{}
}

// Parse parses HCL or JSON marshaled bytes and return HCL AST
func (s *Service) Parse(src []byte) (*ast.File, error) {
	return hcl.ParseBytes(src)
}

// Fprint pretty-prints (writes) HCL specified `node` in specified `output`
func (s *Service) Fprint(output io.Writer, node ast.Node) error {
	return printer.DefaultConfig.Fprint(output, node)
}
