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

type Content struct {
	SectionsByName map[string]*Section
}

func NewIniContent() *Content {
	return &Content{map[string]*Section{}}
}

func (content *Content) AddSection(section *Section) {
	content.SectionsByName[section.Name] = section
}
