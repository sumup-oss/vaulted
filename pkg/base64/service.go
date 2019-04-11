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

package base64

import (
	"encoding/base64"
)

type Service struct{}

func NewBase64Service() *Service {
	return &Service{}
}

func (s *Service) Serialize(raw []byte) ([]byte, error) {
	encoded := make(
		[]byte,
		base64.StdEncoding.EncodedLen(
			len(raw),
		),
	)

	base64.StdEncoding.Encode(encoded, raw)
	return encoded, nil
}

func (s *Service) Deserialize(encoded []byte) ([]byte, error) {
	dst := make(
		[]byte,
		base64.StdEncoding.DecodedLen(
			len(encoded),
		),
	)

	n, err := base64.StdEncoding.Decode(dst, encoded)
	if err != nil {
		return nil, err
	}

	return dst[:n], nil
}
