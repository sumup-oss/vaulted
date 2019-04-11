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

package payload

import (
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
)

type Payload struct {
	Header     *header.Header
	Passphrase *passphrase.Passphrase
	Content    *content.Content
}

func NewPayload(
	header *header.Header,
	passphrase *passphrase.Passphrase,
	content *content.Content,
) *Payload {
	return &Payload{
		Header:     header,
		Passphrase: passphrase,
		Content:    content,
	}
}
