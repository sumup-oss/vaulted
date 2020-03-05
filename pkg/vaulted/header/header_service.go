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

package header

import (
	"errors"
	"fmt"
	"strings"

	"github.com/sumup-oss/vaulted/pkg/vaulted"
)

const (
	headerPartSeparator = ";"
)

var (
	headerAllowedNames    = []string{defaultName}
	headerAllowedVersions = []string{defaultVersion}

	errHeadersPartsMismatch = errors.New("did not find exactly 2 header parts")
	errHeaderNameInvalid    = fmt.Errorf(
		"did not find name equal to any of allowed header names: %#v",
		headerAllowedNames,
	)
	errHeaderVersionInvalid = fmt.Errorf(
		"did not find version equal to any of allowed header versions: %#v",
		headerAllowedVersions,
	)
	errSerializeBlankHeaderName = errors.New(
		"failed to serialize blank header name",
	)
	errSerializeBlankHeaderVersion = errors.New(
		"failed to serialize blank header version",
	)
)

type HeaderService struct{}

func NewHeaderService() *HeaderService {
	return &HeaderService{}
}

func (s *HeaderService) Serialize(header *Header) ([]byte, error) {
	if len(header.Name) < 1 {
		return nil, errSerializeBlankHeaderName
	}

	if len(header.Version) < 1 {
		return nil, errSerializeBlankHeaderVersion
	}

	headerParts := []string{
		header.Name,
		header.Version,
	}

	serialized := strings.Join(headerParts, headerPartSeparator)

	return []byte(serialized), nil
}

func (s *HeaderService) Deserialize(content string) (*Header, error) {
	headerParts := strings.Split(content, headerPartSeparator)

	if len(headerParts) != 2 {
		return nil, errHeadersPartsMismatch
	}

	if !vaulted.Contains(headerAllowedNames, headerParts[0]) {
		return nil, errHeaderNameInvalid
	}

	if !vaulted.Contains(headerAllowedVersions, headerParts[1]) {
		return nil, errHeaderVersionInvalid
	}

	header := &Header{
		Name:    headerParts[0],
		Version: headerParts[1],
	}

	return header, nil
}
