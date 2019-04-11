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

package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/palantir/stacktrace"
	"github.com/sumup-oss/go-pkgs/os"
)

const (
	pemBlockPublicKeyName  = "PUBLIC KEY"
	pemBlockPrivateKeyName = "RSA PRIVATE KEY"
)

var (
	errInvalidRsaPublicKey = errors.New("public key is not a rsa public key")
	errDecodePublicKeyPem  = fmt.Errorf(
		"failed to decode PEM block containing public key. Expected PEM block `%s`",
		pemBlockPublicKeyName,
	)
	errDecodePrivateKeyPem = fmt.Errorf(
		"failed to decode PEM block containing private key. Expected PEM block `%s`",
		pemBlockPrivateKeyName,
	)
)

type Service struct {
	osExecutor os.OsExecutor
}

func NewRsaService(osExecutor os.OsExecutor) *Service {
	return &Service{
		osExecutor: osExecutor,
	}
}

func (s *Service) ReadPublicKeyFromPath(publicKeyPath string) (*rsa.PublicKey, error) {
	publicKeyContent, err := s.osExecutor.ReadFile(publicKeyPath)
	if err != nil {
		return nil, stacktrace.Propagate(
			err,
			"unable to read file contents of public key",
		)
	}

	block, _ := pem.Decode(publicKeyContent)
	if block == nil || block.Type != pemBlockPublicKeyName {
		return nil, errDecodePublicKeyPem
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, stacktrace.Propagate(
			err,
			"unable to parse PKCS1 public key",
		)
	}

	switch pub := key.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, errInvalidRsaPublicKey
	}
}

func (s *Service) ReadPrivateKeyFromPath(privateKeyPath string) (*rsa.PrivateKey, error) {
	privateKeyContent, err := s.osExecutor.ReadFile(privateKeyPath)
	if err != nil {
		return nil, stacktrace.Propagate(
			err,
			"unable to read file contents of private key",
		)
	}

	block, _ := pem.Decode(privateKeyContent)
	if block == nil || block.Type != pemBlockPrivateKeyName {
		return nil, errDecodePrivateKeyPem
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, stacktrace.Propagate(
			err,
			"unable to parse PKCS1 private key",
		)
	}

	return key, nil
}

func (s *Service) EncryptPKCS1v15(rand io.Reader, pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	return rsaEncryptPKCS1v15(rand, pub, msg)
}

func (s *Service) DecryptPKCS1v15(rand io.Reader, priv *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsaDecryptPKCS1v15(rand, priv, ciphertext)
}
