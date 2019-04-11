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

package ini

import (
	"github.com/go-ini/ini"
)

const (
	// NOTE: Default section name used by the INI parser.
	defaultSectionName = "DEFAULT"
)

type Service struct{}

func NewIniService() *Service {
	return &Service{}
}

func (s *Service) ReadIniAtPath(path string) (*ini.File, error) {
	cfg, err := ini.LoadSources(
		ini.LoadOptions{
			AllowPythonMultilineValues: true,
			SpaceBeforeInlineComment:   true,
		},
		path,
	)
	if err != nil {
		return nil, err
	}
	return cfg, nil

}

func (s *Service) ParseIniFileContents(file *ini.File) *Content {
	iniContent := NewIniContent()

	for _, section := range file.Sections() {
		if section.Name() == defaultSectionName {
			continue
		}

		iniSection := NewIniSection(section.Name())

		for _, sectionKey := range section.Keys() {
			iniSection.Values = append(
				iniSection.Values,
				NewIniSectionValue(
					sectionKey.Name(),
					sectionKey.Value(),
				),
			)
		}

		iniContent.AddSection(iniSection)
	}
	return iniContent
}
