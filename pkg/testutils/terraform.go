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

package testutils

import (
	"regexp"
)

//nolint:lll
var OldTerraformRegex = regexp.MustCompile(`(?m)"resource"\s+"vault_encrypted_secret"\s+"(?P<resource_name>\w+)"\s+{[\n]\s+"encrypted_data_json"\s+=\s+"(?P<encrypted_data_json>.+)"[\n]\s+"encrypted_passphrase"\s+=\s+"(?P<encrypted_passphrase>.+)"[\n]\s+"path"\s+=\s+"(?P<path>.+)"`)

//nolint:lll
var NewTerraformRegex = regexp.MustCompile(`(?m)"resource"\s+"vaulted_vault_secret"\s+"(?P<resource_name>\w+)"\s+{[\n]\s+"path"\s+=\s+"(?P<path>.+)"[\n]\s+"payload_json"\s+=\s+"(?P<payload_json>.+)[\n]}`)
