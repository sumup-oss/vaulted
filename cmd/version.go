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

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sumup-oss/go-pkgs/os"

	"github.com/sumup-oss/vaulted/internal/version"
)

func NewVersionCmd(
	osExecutor os.OsExecutor,
) *cobra.Command {
	cmdInstance := &cobra.Command{
		Use:   "version",
		Short: "Print the version of vaulted",
		Long:  `Print the version of vaulted.`,
		RunE: func(command *cobra.Command, args []string) error {
			fmt.Fprintf(
				osExecutor.Stdout(),
				version.Version,
			)
			return nil
		},
	}

	return cmdInstance
}
