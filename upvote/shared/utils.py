# Copyright 2017 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Utilities common to the project."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import re


def CamelToSnakeCase(input_string):
  """Converts camelCase to snake_case."""

  # Prepend every uppercase character with an underscore
  # e.g. camelCase -> camel_Case
  with_underscores = re.sub(r'([A-Z])', r'_\1', input_string)

  # Ensure a name starting with an uppercase letter does not have an underscore
  # e.g. CamelCase -> _Camel_Case -> Camel_Case
  without_leading_underscore = with_underscores.lstrip('_')

  # Convert all characters to lowercase
  # e.g. camel_Case -> camel_case
  return without_leading_underscore.lower()
