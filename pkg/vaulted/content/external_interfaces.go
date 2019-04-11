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

package content

type base64Service interface {
	Serialize(raw []byte) ([]byte, error)
	Deserialize(encoded []byte) ([]byte, error)
}

type aesService interface {
	EncryptCBC(key []byte, plaintext []byte) ([]byte, error)
	DecryptCBC(key []byte, ciphertext []byte) ([]byte, error)
	EncryptGCM(key []byte, plaintext []byte) ([]byte, error)
	DecryptGCM(key []byte, ciphertext []byte) ([]byte, error)
}
