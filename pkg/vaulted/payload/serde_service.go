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
	"errors"
	"fmt"
	"strings"

	"github.com/palantir/stacktrace"

	"github.com/sumup-oss/vaulted/pkg/vaulted"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
)

const (
	HeaderPartSeparator        = ";"
	EncryptionPayloadSeparator = "::"
)

var (
	HeaderAllowedNames    = []string{header.DefaultName}
	headerAllowedVersions = []string{header.DefaultVersion}

	ErrInvalidPayloadParts = errors.New(
		"invalid encryption payload. it must be in format of " +
			"`<header>;;<encryption_passphrase>;;<encryption_payload>`",
	)
	ErrEmptyHeader              = errors.New("invalid header. empty")
	ErrEmptyEncryptedPassphrase = errors.New("invalid encrypted passphrase. empty")
	ErrEmptyEncryptedContent    = errors.New("invalid encrypted payload. empty")
	ErrHeadersPartsMismatch     = errors.New("did not find exactly 2 header parts")
	ErrHeaderNameInvalid        = fmt.Errorf(
		"did not find name equal to any of allowed header names: %#v",
		HeaderAllowedNames,
	)
	ErrHeaderVersionInvalid = fmt.Errorf(
		"did not find version equal to any of allowed header versions: %#v",
		headerAllowedVersions,
	)
	ErrSerializeBlankHeaderName = errors.New(
		"failed to serialize blank header name",
	)
	ErrSerializeBlankHeaderVersion = errors.New(
		"failed to serialize blank header version",
	)
)

type SerdeService struct {
	b64Serde base64Serde
}

func NewSerdeService(b64Serde base64Serde) *SerdeService {
	return &SerdeService{
		b64Serde: b64Serde,
	}
}

func (s *SerdeService) serializeHeader(header *header.Header) ([]byte, error) {
	if len(header.Name) < 1 {
		return nil, ErrSerializeBlankHeaderName
	}

	if len(header.Version) < 1 {
		return nil, ErrSerializeBlankHeaderVersion
	}

	headerParts := []string{
		header.Name,
		header.Version,
	}

	serialized := strings.Join(headerParts, HeaderPartSeparator)

	return []byte(serialized), nil
}

func (s *SerdeService) deserializeHeader(serialized string) (*header.Header, error) {
	headerParts := strings.Split(serialized, HeaderPartSeparator)

	if len(headerParts) != 2 {
		return nil, ErrHeadersPartsMismatch
	}

	if !vaulted.Contains(HeaderAllowedNames, headerParts[0]) {
		return nil, ErrHeaderNameInvalid
	}

	if !vaulted.Contains(headerAllowedVersions, headerParts[1]) {
		return nil, ErrHeaderVersionInvalid
	}

	header := &header.Header{
		Name:    headerParts[0],
		Version: headerParts[1],
	}

	return header, nil
}

func (s *SerdeService) deserializeEncryptedPassphrase(serialized string) (*passphrase.EncryptedPassphrase, error) {
	deserialized, err := s.b64Serde.Deserialize(
		[]byte(serialized),
	)
	if err != nil {
		return nil, stacktrace.Propagate(
			err,
			"failed to deserialize base64 encoded encrypted passphrase",
		)
	}

	return passphrase.NewEncryptedPassphrase(deserialized), nil
}

func (s *SerdeService) deserializeEncryptedContent(serialized string) (*content.EncryptedContent, error) {
	deserialized, err := s.b64Serde.Deserialize(
		[]byte(serialized),
	)
	if err != nil {
		return nil, stacktrace.Propagate(
			err,
			"failed to deserialize base64 encoded encrypted content",
		)
	}

	return content.NewEncryptedContent(deserialized), nil
}

func (s *SerdeService) Serialize(encryptedPayload *EncryptedPayload) ([]byte, error) {
	serializedHeader, err := s.serializeHeader(encryptedPayload.Header)
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed to serialize encrypted payload's header")
	}

	payloadParts := []string{
		string(serializedHeader),
	}

	serializedEncryptedPassphrase, err := s.b64Serde.Serialize(encryptedPayload.EncryptedPassphrase.Ciphertext)
	if err != nil {
		return nil, stacktrace.Propagate(
			err,
			"failed to serialize encrypted payload's encrypted passphrase",
		)
	}

	payloadParts = append(
		payloadParts,
		string(serializedEncryptedPassphrase),
	)

	serializedEncryptedContent, err := s.b64Serde.Serialize(encryptedPayload.EncryptedContent.Ciphertext)
	if err != nil {
		return nil, stacktrace.Propagate(
			err,
			"failed to serialize encrypted payload's encrypted content",
		)
	}

	payloadParts = append(
		payloadParts,
		string(serializedEncryptedContent),
	)

	serialized := strings.Join(payloadParts, EncryptionPayloadSeparator)

	return []byte(serialized), nil
}

func (s *SerdeService) Deserialize(encodedContent []byte) (*EncryptedPayload, error) {
	payloadParts := strings.Split(
		string(encodedContent),
		EncryptionPayloadSeparator,
	)

	if len(payloadParts) != 3 {
		return nil, ErrInvalidPayloadParts
	}

	if len(payloadParts[0]) < 1 {
		return nil, ErrEmptyHeader
	}

	parsedHeader, err := s.deserializeHeader(payloadParts[0])
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed to deserialize header")
	}

	if len(payloadParts[1]) < 1 {
		return nil, ErrEmptyEncryptedPassphrase
	}

	encryptedPassphrase, err := s.deserializeEncryptedPassphrase(payloadParts[1])
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed to deserialize encrypted passphrase")
	}

	if len(payloadParts[2]) < 1 {
		return nil, ErrEmptyEncryptedContent
	}

	encryptedContent, err := s.deserializeEncryptedContent(payloadParts[2])
	if err != nil {
		return nil, stacktrace.Propagate(
			err,
			"failed to deserialize encrypted content",
		)
	}

	encryptedPayload := NewEncryptedPayload(parsedHeader, encryptedPassphrase, encryptedContent)

	return encryptedPayload, nil
}
