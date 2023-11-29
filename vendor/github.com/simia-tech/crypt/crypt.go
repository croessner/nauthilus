// Copyright 2018 Philipp Brüll (pb@simia.tech)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crypt

import (
	"fmt"
	"strings"
)

// Crypt hashes the provided password using the provided salt.
func Crypt(password, settings string) (string, error) {
	for prefix, algorithm := range algorithms {
		if strings.HasPrefix(settings, prefix) {
			return algorithm(password, settings)
		}
	}
	return "", fmt.Errorf("no registered algorithm for settings [%s]", settings)
}
