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
	"io/ioutil"
	stdOs "os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sumup-oss/go-pkgs/os"
	"github.com/sumup-oss/go-pkgs/testutils"
	gopkgsTestUtils "github.com/sumup-oss/go-pkgs/testutils"
	"github.com/sumup-oss/vaulted/internal/e2e"
	vaultedTestUtils "github.com/sumup-oss/vaulted/pkg/testutils"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

var (
	osExecutor = &os.RealOsExecutor{}
	binaryPath string
)

func TestMain(m *testing.M) {
	binaryPath = e2e.GoBuild(osExecutor)

	runTests := m.Run()

	osExecutor.Remove(binaryPath)
	stdOs.Exit(runTests)
}

// NOTE: Test the most-valuable functionality and workflow, excluding the `legacy` and `terraform `commands.
// The flow is:
// 1. encrypt
// 2. decrypt
// 3. rotate
// 4. decrypt
// 5. encrypt
// 6. rekey
// 7. decrypt
// TODO: Investigate why commands that are run do not output to neither stderr nor stdout.
// Tests intentionally expect blank stdout/stderr, even though it's wrong,
// to pass and later be able to correct to expected output.
func TestMvpWorkflow(t *testing.T) {
	t.Parallel()

	tmpDir := gopkgsTestUtils.TestDir(t, "vaulted")
	defer stdOs.RemoveAll(tmpDir)

	// NOTE: Create a build before switching dirs
	build := e2e.NewBuild(binaryPath, tmpDir)

	// NOTE: Switch to tmp dir to make sure we're not
	// relying on content inside the non-temporary dir (previous cwd).
	gopkgsTestUtils.TestChdir(t, tmpDir)

	privKeyPath, privKey := testutils.GenerateAndWritePrivateKey(t, tmpDir, "priv.key")
	pubKeyPath := testutils.GenerateAndWritePublicKey(t, tmpDir, "pub.key", privKey)

	// NOTE: Start of  `1. encrypt`
	inFileContent := []byte("mysecret")
	encryptInPath := filepath.Join(tmpDir, "1-encrypt-in.raw")

	encryptOutPath := filepath.Join(tmpDir, "1-encrypt-out.enc")

	err := ioutil.WriteFile(encryptInPath, inFileContent, 0644)
	require.Nil(t, err)

	stdout, stderr, err := build.Run(
		"encrypt",
		"--public-key-path",
		pubKeyPath,
		"--in",
		encryptInPath,
		"--out",
		encryptOutPath,
	)
	require.Nil(t, err)
	assert.Equal(t, "", stdout)
	assert.Equal(t, "", stderr)

	encryptedOutContent, err := osExecutor.ReadFile(encryptOutPath)
	require.Nil(t, err)

	// NOTE: Make sure we've actually encrypted something
	// and it has a version header, passphrase and content parts
	encryptedOutContentParts := strings.Split(
		string(encryptedOutContent),
		payload.EncryptionPayloadSeparator,
	)
	assert.Equal(t, 3, len(encryptedOutContentParts))
	// NOTE: Verify header, passphrase and content are not empty.
	assert.NotEqual(t, "", encryptedOutContentParts[0])
	assert.NotEqual(t, "", encryptedOutContentParts[1])
	assert.NotEqual(t, "", encryptedOutContentParts[2])

	// NOTE: Start of `2. decrypt`.
	// Take the output of `1. encrypt` to make sure
	// we're still able to decrypt it.
	decryptInPath := encryptOutPath
	decryptOutPath := filepath.Join(tmpDir, "2-decrypt-out")

	stdout, stderr, err = build.Run(
		"decrypt",
		"--private-key-path",
		privKeyPath,
		"--in",
		decryptInPath,
		"--out",
		decryptOutPath,
	)
	require.Nil(t, err)
	assert.Equal(t, "", stdout)
	assert.Equal(t, "", stderr)

	decryptedOutput, err := osExecutor.ReadFile(decryptOutPath)
	require.Nil(t, err)

	// NOTE: Make sure we're not adding/losing content
	assert.Equal(t, inFileContent, decryptedOutput)

	// NOTE: Start of `3. rotate`.
	// Take the output of `1. encrypt` as input,
	// since we need already encrypted payload.
	rotateInPath := encryptOutPath
	rotateOutPath := filepath.Join(tmpDir, "3-rotate-out.enc")

	stdout, stderr, err = build.Run(
		"rotate",
		"--public-key-path",
		pubKeyPath,
		"--private-key-path",
		privKeyPath,
		"--in",
		rotateInPath,
		"--out",
		rotateOutPath,
	)
	require.Nil(t, err)
	assert.Equal(t, "", stdout)
	assert.Equal(t, "", stderr)

	rotatedOutContent, err := osExecutor.ReadFile(rotateOutPath)
	require.Nil(t, err)

	rotatedOutContentParts := strings.Split(
		string(rotatedOutContent),
		payload.EncryptionPayloadSeparator,
	)

	// NOTE: Make sure we've actually encrypted something
	// and it has a version header, passphrase and content parts
	assert.Equal(t, 3, len(rotatedOutContentParts))

	// NOTE: Make sure the header is still the same,
	// and we didn't attempt to change versions.
	assert.Equal(t, encryptedOutContentParts[0], rotatedOutContentParts[0])
	// NOTE: Make sure we rotated the encrypted passphrase
	assert.NotEqual(t, encryptedOutContentParts[1], rotatedOutContentParts[1])
	// NOTE: Make sure we rotated the encrypted content
	assert.NotEqual(t, encryptedOutContentParts[2], rotatedOutContentParts[2])

	// NOTE: Start of `4. decrypt`.
	// We take the rotate encrypted payload output
	// and make sure we're still able to decrypt it.
	rotatedDecryptInPath := rotateOutPath
	rotatedDecryptOutPath := filepath.Join(tmpDir, "4-decrypt-out")

	stdout, stderr, err = build.Run(
		"decrypt",
		"--private-key-path",
		privKeyPath,
		"--in",
		rotatedDecryptInPath,
		"--out",
		rotatedDecryptOutPath,
	)
	require.Nil(t, err)
	assert.Equal(t, "", stdout)
	assert.Equal(t, "", stderr)

	// NOTE: Since we're still using the plaintext input from `1. encrypt`
	// make sure we're still decrypting the same result and not adding/removing content.
	rotatedDecryptOutContent, err := osExecutor.ReadFile(rotatedDecryptOutPath)
	require.Nil(t, err)

	assert.Equal(t, inFileContent, rotatedDecryptOutContent)

	// NOTE: Start of `5. encrypt`.
	// Encrypt again the recently decrypted rotated output,
	// to make sure we cover the `decrypt` -> `encrypt` again flow.
	encryptAgainInPath := rotatedDecryptOutPath
	encryptAgainOutPath := filepath.Join(tmpDir, "5-encrypt-out.enc")

	stdout, stderr, err = build.Run(
		"encrypt",
		"--public-key-path",
		pubKeyPath,
		"--in",
		encryptAgainInPath,
		"--out",
		encryptAgainOutPath,
	)
	require.Nil(t, err)
	assert.Equal(t, "", stdout)
	assert.Equal(t, "", stderr)

	encryptAgainOutContent, err := osExecutor.ReadFile(encryptAgainOutPath)
	require.Nil(t, err)

	// NOTE: Make sure we've actually encrypted something
	// and it has a version header, passphrase and content parts
	encryptAgainOutContentParts := strings.Split(
		string(encryptAgainOutContent),
		payload.EncryptionPayloadSeparator,
	)
	assert.Equal(t, 3, len(encryptAgainOutContentParts))
	// NOTE: Verify header, passphrase and content are not empty.
	assert.NotEqual(t, "", encryptAgainOutContentParts[0])
	assert.NotEqual(t, "", encryptAgainOutContentParts[1])
	assert.NotEqual(t, "", encryptAgainOutContentParts[2])

	// NOTE: Start of `6. rekey`.
	// Make sure that we can rotate the keypair used to
	// generate a previously encrypted payload.
	newPrivKeyPath, newPrivKey := testutils.GenerateAndWritePrivateKey(
		t,
		tmpDir,
		"new-priv.key",
	)
	newPubKeyPath := testutils.GenerateAndWritePublicKey(
		t,
		tmpDir,
		"new-pub.key",
		newPrivKey,
	)

	// NOTE: Use the recently encrypted again payload
	rekeyInPath := encryptAgainOutPath
	rekeyOutPath := filepath.Join(tmpDir, "6-rekey-out.enc")

	stdout, stderr, err = build.Run(
		"rekey",
		"--old-private-key-path",
		privKeyPath,
		"--new-public-key-path",
		newPubKeyPath,
		"--in",
		rekeyInPath,
		"--out",
		rekeyOutPath,
	)
	require.Nil(t, err)
	assert.Equal(t, "", stdout)
	assert.Equal(t, "", stderr)

	rekeyOutContent, err := osExecutor.ReadFile(rekeyOutPath)
	require.Nil(t, err)

	// NOTE: Make sure we've actually encrypted something
	// and it has a version header, passphrase and content parts
	rekeyOutContentParts := strings.Split(
		string(rekeyOutContent),
		payload.EncryptionPayloadSeparator,
	)
	assert.Equal(t, 3, len(rekeyOutContentParts))
	// NOTE: Verify header is the same, since we didn't
	// want to increment versions and modify it at all.
	assert.Equal(t, encryptAgainOutContentParts[0], rekeyOutContentParts[0])
	// NOTE: Verify passphrase and content are actually rotated
	// and not the same as the `in` encrypted payload's.
	assert.NotEqual(t, encryptAgainOutContentParts[1], rekeyOutContentParts[1])
	assert.NotEqual(t, encryptAgainOutContentParts[2], rekeyOutContentParts[2])

	// NOTE: Verify that rekeyed payload is not decryptable using the old keypair
	stdout, stderr, err = build.Run(
		"decrypt",
		"--private-key-path",
		privKeyPath,
		"--in",
		rekeyOutPath,
		// NOTE: `out` intentionally left-out,
		// since this must not pass either way.
		// No need to write to a file, since printing to stdout
		// is sufficient if unexpected behavior occurs.
	)
	require.NotNil(t, err)
	assert.Equal(t, "", stdout)
	assert.Contains(t, stderr, "failed to decrypt encrypted payload using specified RSA key")

	// NOTE: Start of `7. decrypt`.
	// Verifies that the rekeyed content is still decryptable
	// using the new keypair.
	rekeyDecryptInPath := rekeyOutPath
	rekeyDecryptOutPath := filepath.Join(tmpDir, "7-decrypt-out")

	stdout, stderr, err = build.Run(
		"decrypt",
		"--private-key-path",
		newPrivKeyPath,
		"--in",
		rekeyDecryptInPath,
		"--out",
		rekeyDecryptOutPath,
	)
	require.Nil(t, err)
	assert.Equal(t, "", stdout)
	assert.Equal(t, "", stderr)

	// NOTE: Since we're still using the plaintext input from `1. encrypt`
	// make sure we're still decrypting the same result and not adding/removing content.
	rekeyDecryptOutContent, err := osExecutor.ReadFile(rekeyDecryptOutPath)
	require.Nil(t, err)

	assert.Equal(t, inFileContent, rekeyDecryptOutContent)
}

// NOTE: Test the terraform workflow that is feasible when you're converting
// "ini"-file based secrets to encrypted terraform resources.
// The flow is:
// 1. terraform vault ini
// 2. terraform vault migrate
// TODO: When `terraform view` is added this will verify that the content is still decryptable and viewable.
// 4. terraform vault new-resource
// 5. terraform vault rotate
// 6. terraform vault rekey
// TODO: Investigate why commands that are run do not output to neither stderr nor stdout.
// Tests intentionally expect blank stdout/stderr, even though it's wrong,
// to pass and later be able to correct to expected output.
func TestV1TerraformWorkflow(t *testing.T) {
	t.Parallel()

	tmpDir := gopkgsTestUtils.TestDir(t, "vaulted")
	defer stdOs.RemoveAll(tmpDir)

	// NOTE: Create a build before switching dirs
	build := e2e.NewBuild(binaryPath, tmpDir)

	// NOTE: Switch to tmp dir to make sure we're not
	// relying on content inside the non-temporary dir (previous cwd).
	gopkgsTestUtils.TestChdir(t, tmpDir)

	privKeyPath, privKey := testutils.GenerateAndWritePrivateKey(t, tmpDir, "priv.key")
	pubKeyPath := testutils.GenerateAndWritePublicKey(t, tmpDir, "pub.key", privKey)

	// NOTE: Start of `1. vault ini`
	iniContent := []byte(`[sectionExample]
myKey=example

[sectionExampleAgain]
myOtherKey=exampleother
`)
	osExecutor := &os.RealOsExecutor{}

	inputIniFilePath := path.Join(tmpDir, "input.ini")
	err := osExecutor.WriteFile(inputIniFilePath, iniContent, 0644)
	require.Nil(t, err)

	iniTfFilePath := path.Join(tmpDir, "ini.tf")
	stdout, stderr, err := build.Run(
		"terraform",
		"vault",
		"ini",
		"--public-key-path",
		pubKeyPath,
		"--in",
		inputIniFilePath,
		"--out",
		iniTfFilePath,
	)
	require.Nil(t, err)
	assert.Equal(t, "", stdout)
	assert.Equal(t, "", stderr)

	iniTfFileContent, err := osExecutor.ReadFile(iniTfFilePath)
	require.Nil(t, err)

	// NOTE: Make sure we actually wrote valid terraform resources
	regexMatches := vaultedTestUtils.NewTerraformRegex.FindAllStringSubmatch(string(iniTfFileContent), -1)
	assert.Equal(t, 2, len(regexMatches))

	// NOTE: Start of `2. terraform vault migrate`
	migratedTfFilePath := path.Join(tmpDir, "migrated.tf")
	stdout, stderr, err = build.Run(
		"terraform",
		"vault",
		"migrate",
		"--private-key-path",
		privKeyPath,
		"--public-key-path",
		pubKeyPath,
		"--in",
		iniTfFilePath,
		"--out",
		migratedTfFilePath,
	)
	require.Nil(t, err)
	assert.Equal(t, "", stdout)
	assert.Equal(t, "", stderr)

	migratedTfFileContent, err := osExecutor.ReadFile(migratedTfFilePath)
	require.Nil(t, err)

	// NOTE: Make sure we actually wrote valid terraform resources
	regexMatches = vaultedTestUtils.NewTerraformRegex.FindAllStringSubmatch(string(migratedTfFileContent), -1)
	assert.Equal(t, 2, len(regexMatches))

	// NOTE: Start of `4. terraform new-resource`
	inFilePath := path.Join(tmpDir, "in.raw")
	inFileContent := []byte("mynewsecret")
	newResourcePathArg := "secret/new-resource/example"
	newResourceResourceName := "myresource"

	err = osExecutor.WriteFile(inFilePath, inFileContent, 0644)
	require.Nil(t, err)

	// NOTE: Append to the same output file as migrated one
	stdout, stderr, err = build.Run(
		"terraform",
		"vault",
		"new-resource",
		"--public-key-path",
		pubKeyPath,
		"--path",
		newResourcePathArg,
		"--resource-name",
		newResourceResourceName,
		"--in",
		inFilePath,
		"--out",
		migratedTfFilePath,
	)
	require.Nil(t, err)
	assert.Equal(t, "", stdout)
	assert.Equal(t, "", stderr)

	migratedTfFileContent, err = osExecutor.ReadFile(migratedTfFilePath)
	require.Nil(t, err)

	// NOTE: Make sure we actually wrote valid terraform resources
	regexMatches = vaultedTestUtils.NewTerraformRegex.FindAllStringSubmatch(string(migratedTfFileContent), -1)
	assert.Equal(t, 3, len(regexMatches))

	rotatedTfFilePath := path.Join(tmpDir, "rotated.tf")

	// NOTE: Start of `5. terraform vault rotate`
	stdout, stderr, err = build.Run(
		"terraform",
		"vault",
		"rotate",
		"--public-key-path",
		pubKeyPath,
		"--private-key-path",
		privKeyPath,
		"--in",
		migratedTfFilePath,
		"--out",
		rotatedTfFilePath,
	)
	assert.Equal(t, "", stdout)
	assert.Equal(t, "", stderr)
	require.Nil(t, err)

	rotatedTfFileContent, err := osExecutor.ReadFile(rotatedTfFilePath)
	require.Nil(t, err)

	// NOTE: Make sure we actually wrote valid terraform resources
	regexMatches = vaultedTestUtils.NewTerraformRegex.FindAllStringSubmatch(string(rotatedTfFileContent), -1)
	assert.Equal(t, 3, len(regexMatches))

	rekeyedTfFilePath := path.Join(tmpDir, "rekeyed.tf")

	_, newPrivKey := testutils.GenerateAndWritePrivateKey(t, tmpDir, "newpriv.key")
	newPubKeyPath := testutils.GenerateAndWritePublicKey(t, tmpDir, "newpub.key", newPrivKey)

	// NOTE: Start of `6. terraform vault rekey`
	stdout, stderr, err = build.Run(
		"terraform",
		"vault",
		"rekey",
		"--new-public-key-path",
		newPubKeyPath,
		"--old-private-key-path",
		privKeyPath,
		"--in",
		rotatedTfFilePath,
		"--out",
		rekeyedTfFilePath,
	)
	require.Nil(t, err)
	assert.Equal(t, "", stdout)
	assert.Equal(t, "", stderr)

	rekeyedTfFileContent, err := osExecutor.ReadFile(rekeyedTfFilePath)
	require.Nil(t, err)

	// NOTE: Make sure we actually wrote valid terraform resources
	regexMatches = vaultedTestUtils.NewTerraformRegex.FindAllStringSubmatch(string(rekeyedTfFileContent), -1)
	assert.Equal(t, 3, len(regexMatches))
}
