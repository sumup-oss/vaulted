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
	"github.com/spf13/cobra"
	"github.com/sumup-oss/go-pkgs/os"

	"github.com/sumup-oss/vaulted/cmd/external_interfaces"
	terraformCmd "github.com/sumup-oss/vaulted/cmd/terraform"
)

func NewTerraformCmd(
	osExecutor os.OsExecutor,
	rsaSvc external_interfaces.RsaService,
	iniSvc external_interfaces.IniService,
	encryptedPassphraseSvc external_interfaces.EncryptedPassphraseService,
	legacyEncryptedContentSvc external_interfaces.EncryptedContentService,
	v1EncryptedPayloadSvc external_interfaces.EncryptedPayloadService,
	hclSvc external_interfaces.HclService,
	tfEncryptionMigrationSvc external_interfaces.TerraformEncryptionMigrationService,
) *cobra.Command {
	cmdInstance := &cobra.Command{
		Use:   "terraform",
		Short: "Terraform resources related commands",
		Long:  "Terraform resources related commands",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmdInstance.AddCommand(
		terraformCmd.NewVaultCmd(
			osExecutor,
			rsaSvc,
			iniSvc,
			encryptedPassphraseSvc,
			legacyEncryptedContentSvc,
			v1EncryptedPayloadSvc,
			hclSvc,
			tfEncryptionMigrationSvc,
		),
	)

	return cmdInstance
}
