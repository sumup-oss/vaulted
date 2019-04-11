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

package terraform

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewTerraformContent(t *testing.T) {
	t.Run(
		"it creates new terraform content with already initialized `resourcesByName`",
		func(t *testing.T) {
			t.Parallel()

			actual := NewTerraformContent()

			assert.IsType(t, actual, &Content{})
			assert.NotNil(t, actual.ResourcesByName)
		},
	)
}

func TestContent_AddResource(t *testing.T) {
	t.Run(
		"with not already present resource, it adds resource by `name` to `ResourcesByName`",
		func(t *testing.T) {
			t.Parallel()

			resource := NewTerraformResource("example", "test_subject")

			tfContent := NewTerraformContent()

			assert.Equal(t, 0, len(tfContent.ResourcesByName))

			tfContent.AddResource(resource)

			assert.Equal(t, 1, len(tfContent.ResourcesByName))

			assert.Equal(t, tfContent.ResourcesByName[resource.Name], resource)
		},
	)

	t.Run(
		"with  already present resource, it overrides already present resource by `name`",
		func(t *testing.T) {
			t.Parallel()

			resource := NewTerraformResource("example", "test_subject")
			tfContent := NewTerraformContent()
			tfContent.AddResource(resource)
			assert.Equal(t, 1, len(tfContent.ResourcesByName))

			newResource := NewTerraformResource("example", "new_subject")

			tfContent.AddResource(newResource)

			assert.Equal(t, 1, len(tfContent.ResourcesByName))

			assert.Equal(t, tfContent.ResourcesByName[newResource.Name], newResource)
		},
	)
}
