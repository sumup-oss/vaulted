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

package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/palantir/stacktrace"
	"github.com/sumup-oss/go-pkgs/os"
)

func ReadFromStdin(osExecutor os.OsExecutor, promptMessage string) ([]byte, error) {
	fmt.Fprint(osExecutor.Stdout(), promptMessage)

	value, err := readPassword(osExecutor.Stdin())
	if err != nil {
		return nil, stacktrace.Propagate(
			err,
			"failed to read content of stdin tmp file",
		)
	}

	if value == nil {
		return nil, errors.New("empty value")
	}

	return value, nil
}

func readPassword(reader io.Reader) ([]byte, error) {
	var readContent []byte

	// NOTE: Since we're acting based on single characters,
	// read only 1 byte at a time.
	var readBuff [1]byte

	for {
		n, err := reader.Read(readBuff[:])

		// NOTE: Discard any return characters
		if n > 0 && readBuff[0] != '\r' {
			if readBuff[0] == '\n' {
				return readContent, nil
			}

			readContent = append(readContent, readBuff[0])
		}

		if err != nil {
			// NOTE: Accept EOF-terminated content if not empty,
			// as other stdin-reading CLIs do.
			if err == io.EOF && len(readContent) > 0 {
				err = nil
			}

			return readContent, err
		}
	}
}
