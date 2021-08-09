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

	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/rsa"
)

func NewRootCmd(
	osExecutor os.OsExecutor,
	rsaSvc *rsa.Service,
	aesSvc *aes.Service,
	base64Svc *base64.Service,
	hclSvc *hcl.Service,
) *cobra.Command {
	cmdInstance := &cobra.Command{
		Use:   "vaulted",
		Short: "Vault encrypt/decrypt cli utility",
		Long:  "Vault encrypt/decrypt using asymmetric RSA keys and AES",
		// NOTE: Silence errors and usage since it'll log twice,
		// due to bad cobra API design and the fact that `RunE` actually returns the error
		// that it's going to log either way.
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmdInstance.AddCommand(
		NewVersionCmd(osExecutor),
		NewEncryptCommand(osExecutor, rsaSvc, base64Svc, aesSvc),
		NewDecryptCommand(osExecutor, rsaSvc, base64Svc, aesSvc),
		NewRotateCommand(osExecutor, rsaSvc, base64Svc, aesSvc),
		NewRekeyCommand(osExecutor, rsaSvc, base64Svc, aesSvc),
		NewTerraformCmd(osExecutor, rsaSvc, hclSvc, base64Svc, aesSvc),
	)

	return cmdInstance
}
