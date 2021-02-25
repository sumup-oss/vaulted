package terraform

import (
	"github.com/spf13/cobra"
	"github.com/sumup-oss/go-pkgs/os"

	"github.com/sumup-oss/vaulted/cmd/external_interfaces"
	"github.com/sumup-oss/vaulted/cmd/terraform/vault"
)

func NewVaultCmd(
	osExecutor os.OsExecutor,
	rsaSvc external_interfaces.RsaService,
	iniSvc external_interfaces.IniService,
	encryptedPassphraseSvc external_interfaces.EncryptedPassphraseService,
	legacyEncryptedContentSvc external_interfaces.EncryptedContentService,
	v1EncryptedPayloadSvc external_interfaces.EncryptedPayloadService,
	hclSvc external_interfaces.HclService,
	terraformSvc external_interfaces.TerraformService,
	tfEncryptionMigrationSvc external_interfaces.TerraformEncryptionMigrationService,
) *cobra.Command {
	cmdInstance := &cobra.Command{
		Use:   "vault",
		Short: "github.com/sumup-oss/terraform-provider-vaulted resources related commands",
		Long:  "github.com/sumup-oss/terraform-provider-vaulted resources related commands",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmdInstance.AddCommand(
		vault.NewNewResourceCommand(
			osExecutor,
			rsaSvc,
			encryptedPassphraseSvc,
			v1EncryptedPayloadSvc,
			hclSvc,
			terraformSvc,
		),
		vault.NewMigrateCommand(
			osExecutor,
			rsaSvc,
			encryptedPassphraseSvc,
			legacyEncryptedContentSvc,
			v1EncryptedPayloadSvc,
			hclSvc,
			terraformSvc,
			tfEncryptionMigrationSvc,
		),
		vault.NewRotateCommand(
			osExecutor,
			rsaSvc,
			encryptedPassphraseSvc,
			v1EncryptedPayloadSvc,
			hclSvc,
			terraformSvc,
			tfEncryptionMigrationSvc,
		),
		vault.NewRekeyCommand(
			osExecutor,
			rsaSvc,
			encryptedPassphraseSvc,
			v1EncryptedPayloadSvc,
			hclSvc,
			terraformSvc,
			tfEncryptionMigrationSvc,
		),
		vault.NewIniCommand(
			osExecutor,
			rsaSvc,
			iniSvc,
			encryptedPassphraseSvc,
			v1EncryptedPayloadSvc,
			hclSvc,
			terraformSvc,
			tfEncryptionMigrationSvc,
		),
	)

	return cmdInstance
}
