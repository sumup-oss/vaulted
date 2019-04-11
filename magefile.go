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

// +build mage

package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

const (
	testReportFileName = "test-report.xml"
	coverageFileName   = "coverage.txt"
	coberturaFileName  = "coverage.xml"
)

var (
	coberturaPathReplaceRegex = regexp.MustCompile(`github[.]com/sumup-oss/vaulted`)
)

func Lint() error {
	return sh.Run("golangci-lint", "run")
}

// Test runs all the tests with coverage, but no JUnit report.
func Test() error {
	args := []string{"test", "./...", "-cover"}
	if mg.Verbose() {
		args = append(args, "-v")
	}

	return sh.Run("go", args...)
}

// TestWithReports runs all tests with coverage and generates JUnit report in 'test-report.xml'.
func TestWithReports() error {
	return runTestsWithReports(testReportFileName)
}

func runTestsWithReports(reportFileName string) error {
	testIn := &bytes.Buffer{}
	testOut := io.MultiWriter(os.Stdout, testIn)
	args := []string{"test", "./...", "-coverprofile", coverageFileName}
	if mg.Verbose() {
		args = append(args, "-v")
	}

	testCmd := exec.Command("go", args...)
	testCmd.Stdout = testOut
	testCmd.Stderr = testOut
	testErr := testCmd.Run()
	if testIn.Len() == 0 {
		return testErr
	}

	reportFile, err := os.Create(reportFileName)
	defer reportFile.Close()
	if err != nil {
		return err
	}

	reportCmd := exec.Command("go-junit-report", "-set-exit-code")
	reportCmd.Stdout = reportFile
	reportCmd.Stderr = os.Stderr
	reportCmd.Stdin = testIn
	err = reportCmd.Run()
	if err != nil {
		return err
	}

	coverage, err := ioutil.ReadFile(coverageFileName)
	if err != nil {
		return err
	}
	currentDir, err := os.Getwd()
	if err != nil {
		return err
	}
	coverage = coberturaPathReplaceRegex.ReplaceAll(coverage, []byte(currentDir))

	coberturaFile, err := os.Create(coberturaFileName)
	if err != nil {
		return err
	}
	defer coberturaFile.Close()

	coberturaCmd := exec.Command("gocover-cobertura")
	coberturaCmd.Stdout = coberturaFile
	coberturaCmd.Stderr = os.Stderr
	coberturaCmd.Stdin = bytes.NewReader(coverage)

	return coberturaCmd.Run()
}
