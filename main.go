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

package main

import (
	"fmt"

	"github.com/sumup-oss/go-pkgs/os"

	"github.com/sumup-oss/vaulted/cmd"
	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/hcl"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/rsa"
)

func main() {
	// NOTE: This is pretty much what a dependency injection container would do.
	// It's important to initialize and pass only the most generic services
	// that do not change between business logic implementation.
	osExecutor := &os.RealOsExecutor{}
	rsaSvc := rsa.NewRsaService(osExecutor)
	pkcs7Svc := pkcs7.NewPkcs7Service()
	aesSvc := aes.NewAesService(pkcs7Svc)
	base64Svc := base64.NewBase64Service()
	hclSvc := hcl.NewHclService()

	err := cmd.NewRootCmd(
		osExecutor,
		rsaSvc,
		aesSvc,
		base64Svc,
		hclSvc,
	).Execute()
	if err == nil {
		return
	}

	//nolint:errcheck,staticcheck
	fmt.Fprintf(osExecutor.Stderr(), err.Error())
	osExecutor.Exit(1)
}
