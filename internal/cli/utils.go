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

package cli

import (
	"fmt"
	stdOs "os"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/palantir/stacktrace"
	"github.com/sumup-oss/go-pkgs/os"
)

func WriteHCLout(
	osExecutor os.OsExecutor,
	outFilePath string,
	hclFile *hclwrite.File,
) error {
	var err error

	if outFilePath == "" {
		_, _ = fmt.Fprintln(osExecutor.Stdout(), "Terraform HCL below:")

		_, err = osExecutor.Stdout().Write(hclFile.Bytes())
		if err != nil {
			return stacktrace.Propagate(
				err,
				"failed to write HCL to stdout",
			)
		}
	} else {
		srcFd, err := osExecutor.OpenFile(outFilePath, stdOs.O_APPEND|stdOs.O_CREATE|stdOs.O_RDWR, 0755)
		if err != nil {
			return stacktrace.Propagate(err, "failed to open/create file at out file path")
		}
		defer srcFd.Close()

		_, err = srcFd.Write(hclFile.Bytes())
		if err != nil {
			return stacktrace.Propagate(
				err,
				"failed to write terraform HCL at out file path",
			)
		}

		err = srcFd.Sync()
		if err != nil {
			return stacktrace.Propagate(
				err,
				"failed to sync terraform HCL writes to  out file path file",
			)
		}
	}

	return nil
}
