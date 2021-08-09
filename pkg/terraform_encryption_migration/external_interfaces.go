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

package terraform_encryption_migration

import (
	"github.com/hashicorp/hcl/v2/hclwrite"

	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

type terraformService interface {
	ModifyInPlaceHclAst(
		hclParser hcl.Parser,
		hclBytes []byte,
		blockItemVisitorFunc func(block *hclwrite.Block) error,
	) (*hclwrite.File, error)
}

type PayloadDecrypter interface {
	Decrypt(encryptedPayload *payload.EncryptedPayload) (*payload.Payload, error)
}

type PayloadEncrypter interface {
	Encrypt(payload *payload.Payload) (*payload.EncryptedPayload, error)
}
