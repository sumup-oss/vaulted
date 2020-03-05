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

	"github.com/sumup-oss/vaulted/cmd/external_interfaces"
	"github.com/sumup-oss/vaulted/cmd/legacy"
	"github.com/sumup-oss/vaulted/pkg/ini"
	"github.com/sumup-oss/vaulted/pkg/rsa"
)

func NewLegacyCmd(
	osExecutor os.OsExecutor,
	rsaSvc *rsa.Service,
	iniSvc *ini.Service,
	encryptedPassphraseSvc external_interfaces.EncryptedPassphraseService,
	encryptedContentSvc external_interfaces.EncryptedContentService,
	hclSvc external_interfaces.HclService,
	terraformSvc external_interfaces.TerraformService,
	terraformEncryptionMigrationSvc external_interfaces.TerraformEncryptionMigrationService,
) *cobra.Command {
	cmdInstance := &cobra.Command{
		Use:   "legacy",
		Short: "Legacy Proof-of-concept-phase commands",
		Long:  "Legacy Proof-of-concept-phase commands that are now deprecated",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(osExecutor.Stdout(), "Use `--help` to see available commands")
			return nil
		},
	}

	cmdInstance.AddCommand(
		legacy.NewEncryptCommand(osExecutor, rsaSvc, encryptedPassphraseSvc, encryptedContentSvc),
	)

	cmdInstance.AddCommand(
		legacy.NewDecryptCommand(
			osExecutor,
			rsaSvc,
			encryptedPassphraseSvc,
			encryptedContentSvc,
		),
	)
	cmdInstance.AddCommand(
		legacy.NewIniCommand(
			osExecutor,
			rsaSvc,
			iniSvc,
			encryptedPassphraseSvc,
			encryptedContentSvc,
			hclSvc,
			terraformSvc,
			terraformEncryptionMigrationSvc,
		),
	)

	return cmdInstance
}
