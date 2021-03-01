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
	"fmt"

	hclv2 "github.com/hashicorp/hcl/v2"
)

type ParseErr struct {
	Errs []*Err
}

func NewParseErr(errs []*Err) *ParseErr {
	return &ParseErr{Errs: errs}
}

func (e *ParseErr) Error() string {
	errStr := fmt.Sprintf("Failed to parse HCL, encountered: %d errs. ", len(e.Errs))

	for _, err := range e.Errs {
		errStr += err.Error() + ", "
	}

	return errStr
}

type Err struct {
	diag *hclv2.Diagnostic
}

func NewErr(diag *hclv2.Diagnostic) *Err {
	return &Err{diag: diag}
}

func (e *Err) Error() string {
	if e.diag.Subject != nil {
		return fmt.Sprintf(
			"[%s:%d] %s: %s",
			e.diag.Subject.Filename,
			e.diag.Subject.Start.Line,
			e.diag.Summary,
			e.diag.Detail,
		)
	}

	return fmt.Sprintf("%s: %s", e.diag.Summary, e.diag.Detail)
}
