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
	"fmt"
	stdOs "os"

	"github.com/sumup-oss/vaulted/cmd/external_interfaces"

	"github.com/hashicorp/hcl/hcl/ast"

	"github.com/palantir/stacktrace"
	"github.com/sumup-oss/go-pkgs/os"
)

func writeHCLout(
	osExecutor os.OsExecutor,
	outFilePath string,
	hclSvc external_interfaces.HclService,
	hclFile *ast.File,
	tfSvc external_interfaces.TerraformService,
) error {
	var err error
	if outFilePath == "" {
		fmt.Fprintln(osExecutor.Stdout(), "Terraform HCL below:")
		err = tfSvc.WriteHCLfile(hclSvc, hclFile, osExecutor.Stdout())
		if err != nil {
			return stacktrace.Propagate(
				err,
				"failed to write HCL to stdout",
			)

		}
	} else {
		outFile, err := osExecutor.OpenFile(
			outFilePath,
			stdOs.O_APPEND|stdOs.O_CREATE|stdOs.O_WRONLY,
			0644,
		)
		if err != nil {
			return stacktrace.Propagate(
				err,
				"failed to open file at out file path",
			)
		}

		_, err = outFile.WriteString("\n")
		if err != nil {
			return stacktrace.Propagate(
				err,
				"failed to write newline at out file path",
			)
		}

		err = tfSvc.WriteHCLfile(hclSvc, hclFile, outFile)
		if err != nil {
			return stacktrace.Propagate(
				err,
				"failed to write terraform HCL at out file path",
			)
		}
	}

	return nil
}
