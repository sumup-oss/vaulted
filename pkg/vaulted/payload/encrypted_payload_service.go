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
	"crypto/rsa"
	"errors"
	"strings"

	"github.com/palantir/stacktrace"
)

const (
	EncryptionPayloadSeparator = "::"
)

var (
	errInvalidPayloadParts = errors.New(
		"invalid encryption payload. it must be in format of " +
			"`<header>;;<encryption_passphrase>;;<encryption_payload>`",
	)
	errEmptyHeader              = errors.New("invalid header. empty")
	errEmptyEncryptedPassphrase = errors.New("invalid encrypted passphrase. empty")
	errEmptyEncryptedContent    = errors.New("invalid encrypted payload. empty")
)

type EncryptedPayloadService struct {
	headerService              headerService
	encryptedPassphraseService encryptedPassphraseService
	encryptedContentService    encryptedContentService
}

func NewEncryptedPayloadService(
	headerService headerService,
	encryptedPassphraseService encryptedPassphraseService,
	encryptedContentService encryptedContentService,
) *EncryptedPayloadService {
	return &EncryptedPayloadService{
		headerService:              headerService,
		encryptedPassphraseService: encryptedPassphraseService,
		encryptedContentService:    encryptedContentService,
	}
}

func (s *EncryptedPayloadService) Serialize(encryptedPayload *EncryptedPayload) ([]byte, error) {
	serializedHeader, err := s.headerService.Serialize(encryptedPayload.Header)
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed to serialize encrypted payload's header")
	}

	var payloadParts []string
	payloadParts = append(
		payloadParts,
		string(serializedHeader),
	)

	serializedEncryptedPassphrase, err := s.encryptedPassphraseService.Serialize(
		encryptedPayload.EncryptedPassphrase,
	)
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

	serializedEncryptedContent, err := s.encryptedContentService.Serialize(
		encryptedPayload.EncryptedContent,
	)
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

func (s *EncryptedPayloadService) Deserialize(encodedContent []byte) (*EncryptedPayload, error) {
	payloadParts := strings.Split(
		string(encodedContent),
		EncryptionPayloadSeparator,
	)

	if len(payloadParts) != 3 {
		return nil, errInvalidPayloadParts
	}

	if len(payloadParts[0]) < 1 {
		return nil, errEmptyHeader
	}

	parsedHeader, err := s.headerService.Deserialize(payloadParts[0])
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed to parse header")
	}

	if len(payloadParts[1]) < 1 {
		return nil, errEmptyEncryptedPassphrase
	}

	encryptedPassphrase, err := s.encryptedPassphraseService.Deserialize(
		[]byte(
			payloadParts[1],
		),
	)
	if err != nil {
		return nil, stacktrace.Propagate(
			err,
			"failed to deserialize base64 encoded encrypted passphrase",
		)
	}

	if len(payloadParts[2]) < 1 {
		return nil, errEmptyEncryptedContent
	}

	encryptedContent, err := s.encryptedContentService.Deserialize(
		[]byte(
			payloadParts[2],
		),
	)
	if err != nil {
		return nil, stacktrace.Propagate(
			err,
			"failed to deserialize base64 encoded encrypted content",
		)
	}

	encryptedPayload := NewEncryptedPayload(parsedHeader, encryptedPassphrase, encryptedContent)

	return encryptedPayload, nil
}

func (s *EncryptedPayloadService) Encrypt(publicKey *rsa.PublicKey, payload *Payload) (*EncryptedPayload, error) {
	encryptedPassphrase, err := s.encryptedPassphraseService.Encrypt(publicKey, payload.Passphrase)
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed to encrypt encrypted passphrase")
	}

	encryptedContent, err := s.encryptedContentService.Encrypt(payload.Passphrase, payload.Content)
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed to encrypt encrypted content")
	}

	encryptedPayload := NewEncryptedPayload(
		payload.Header,
		encryptedPassphrase,
		encryptedContent,
	)

	return encryptedPayload, nil
}

func (s *EncryptedPayloadService) Decrypt(
	privateKey *rsa.PrivateKey,
	encryptedPayload *EncryptedPayload,
) (*Payload, error) {
	decryptedPassphrase, err := s.encryptedPassphraseService.Decrypt(
		privateKey,
		encryptedPayload.EncryptedPassphrase,
	)
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed to decrypt encrypted passphrase")
	}

	decryptedContent, err := s.encryptedContentService.Decrypt(
		decryptedPassphrase,
		encryptedPayload.EncryptedContent,
	)
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed to decrypt encrypted content")
	}

	payload := NewPayload(encryptedPayload.Header, decryptedPassphrase, decryptedContent)

	return payload, nil
}
