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
	hclv2 "github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/palantir/stacktrace"
)

// Service is an ad-hoc abstraction
// used to cover-up HashiCorp's bad abstraction
// that is not dependency injectable.
type Service struct{}

func NewHclService() *Service {
	return &Service{}
}

// Parse parses HCL or JSON marshaled bytes and return HCL AST.
func (s *Service) Parse(src []byte) (*hclwrite.File, error) {
	f, diags := hclwrite.ParseConfig(src, "", hclv2.Pos{Line: 1, Column: 1})

	if diags.HasErrors() {
		var errs []*Err
		for _, diag := range diags {
			errs = append(errs, NewErr(diag))
		}

		err := NewParseErr(errs)

		return nil, stacktrace.Propagate(err, "failed to parse HCL")
	}

	return f, nil
}
