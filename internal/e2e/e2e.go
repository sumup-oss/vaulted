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

package e2e

import (
	"bytes"
	"io/ioutil"
	"log"
	stdOs "os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/palantir/stacktrace"
	"github.com/sumup-oss/go-pkgs/os"
)

const (
	pkgPath             = "github.com/sumup-oss/vaulted"
	windowsBinarySuffix = ".exe"
)

type Build struct {
	binaryPath string
	workDir    string
}

func NewBuild(binaryPath, workDir string) *Build {
	return &Build{
		binaryPath: binaryPath,
		workDir:    workDir,
	}
}

func (b *Build) cmd(args ...string) *exec.Cmd {
	//nolint:gosec
	cmd := exec.Command(b.binaryPath, args...)
	cmd.Dir = b.workDir

	// NOTE: Inherit environment of the host/container running the binary,
	// to make sure we're not isolating factors.
	cmd.Env = stdOs.Environ()

	return cmd
}

func (b *Build) Run(args ...string) (string, string, error) {
	cmdInstance := b.cmd(args...)

	var stdoutBuffer, stdErrBuffer bytes.Buffer

	// NOTE: Don't need stdin.
	cmdInstance.Stdin = nil
	cmdInstance.Stdout = &stdoutBuffer
	cmdInstance.Stderr = &stdErrBuffer

	err := cmdInstance.Run()

	return stdoutBuffer.String(), stdErrBuffer.String(), stacktrace.Propagate(err, "failed to run cmd")
}

func GoBuild(osExecutor os.OsExecutor) string {
	tmpFile, err := ioutil.TempFile("", "e2e-vaulted")
	if err != nil {
		log.Fatal(err)
	}

	tmpFilename := tmpFile.Name()

	err = tmpFile.Close()
	if err != nil {
		log.Fatal(err)
	}

	// NOTE: On windows the temp file created in the previous step cannot be overwritten
	err = osExecutor.Remove(tmpFilename)
	if err != nil {
		log.Fatal(err)
	}

	var binaryPath string

	if stdOs.Getenv("GOROOT") == "" {
		binaryPath = "go"
	} else {
		binaryPath = filepath.Join(stdOs.Getenv("GOROOT"), "bin", "go")
	}

	if runtime.GOOS == "windows" {
		binaryPath += windowsBinarySuffix
		tmpFilename += windowsBinarySuffix
	}

	cmd := exec.Command(
		binaryPath,
		"build",
		"-v",
		"-o",
		tmpFilename,
		pkgPath,
	)
	cmd.Stderr = osExecutor.Stderr()
	// NOTE: Don't need stdin.
	cmd.Stdin = nil
	cmd.Stdout = osExecutor.Stderr()

	err = cmd.Run()
	if err != nil {
		log.Fatalf("failed to build executable: %s", err)
	}

	return tmpFilename
}
