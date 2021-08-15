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

package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/palantir/stacktrace"
)

type Service struct {
	cfg *aws.Config
}

func NewService(ctx context.Context, region string) (*Service, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed to load default AWS config")
	}

	if region != "" {
		cfg.Region = region
	}

	return &Service{cfg: &cfg}, nil
}

func (s *Service) Decrypt(ctx context.Context, kmsKeyID string, ciphertext []byte) ([]byte, error) {
	kmsSvc := kms.NewFromConfig(*s.cfg)

	decryptOutput, err := kmsSvc.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob:      ciphertext,
		EncryptionAlgorithm: "RSAES_OAEP_SHA_256",
		KeyId:               aws.String(kmsKeyID),
	})
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed to decrypt using AWS KMS")
	}

	return decryptOutput.Plaintext, nil
}
