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

package passphrase

import "github.com/palantir/stacktrace"

type Service struct{}

func NewService() *Service {
	return &Service{}
}

func (s *Service) GeneratePassphrase(length int) (*Passphrase, error) {
	b := make([]byte, length)

	_, err := randRead(b)
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed to generate random sequence")
	}

	return newPassphrase(b), nil
}
