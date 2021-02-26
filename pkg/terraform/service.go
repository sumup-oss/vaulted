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
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/palantir/stacktrace"

	"github.com/sumup-oss/vaulted/pkg/hcl"
)

type Service struct{}

func NewTerraformService() *Service {
	return &Service{}
}

func (s *Service) ModifyInPlaceHclAst(
	parser hcl.Parser,
	hclBytes []byte,
	blockItemVisitorFunc func(block *hclwrite.Block) error,
) (*hclwrite.File, error) {
	f, err := parser.Parse(hclBytes)
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed to parse HCL")
	}

	body := f.Body()
	if body == nil {
		return nil, stacktrace.NewError("empty body")
	}

	for _, b := range body.Blocks() {
		err := blockItemVisitorFunc(b)
		if err != nil {
			return nil, stacktrace.Propagate(err, "block item visitor failed")
		}
	}

	return f, nil
}
