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

"""Utils for the REST API."""

import re
import string


# Characters we want to replace with spaces
_REPLACE_CHARS = '\t\n\x0b\x0c\r'

# Make a trans table appropriate for string.translate()
_ALLOW_TRANS = string.maketrans(_REPLACE_CHARS, (' ' * len(_REPLACE_CHARS)))

# Make a trans table appropriate for unicode.translate()
_UNICODE_ALLOW_TRANS = {ord(c): u' ' for c in _REPLACE_CHARS}

# Make a table of characters to delete from the string
_DELETE_CHARS = ''.join(map(chr, xrange(128, 256)))


def unicode_to_ascii(value):
  return to_ascii_str(value) if isinstance(value, unicode) else value


def to_ascii_str(s):
  """Given any character variable, return a sanitized ascii string version.

  Turn newlines, tabs, etc into spaces, but strip leading and
  trailing spaces.

  Args:
    s: str or unicode variable.

  Returns:
    String (not unicode) filtered to include no high ascii, unicode, etc.

  Raises:
    TypeError: Passed a non-string/unicode value.
  """
  if s is None:
    return ''

  if not isinstance(s, unicode) and not isinstance(s, str):
    raise TypeError('expected a string or unicode object')

  if isinstance(s, str):
    # Delete chars >=128 to begin with, encode() won't handle them.
    # Also, translate various spacing characters (\n etc) to (space).
    s = s.translate(_ALLOW_TRANS, _DELETE_CHARS)
  else:
    # Translate various spacing characters (\n etc) to (space).
    s = s.translate(_UNICODE_ALLOW_TRANS)

  # Finally, remove any non-ascii characters leftover.
  return s.encode('ascii', 'ignore').strip()


def camel_to_snake_case(input_string):
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


def camel_to_snake_case_with_acronyms(input_string):
  """Converts camelCase to snake_case while retaining acronyms."""

  acronym_matches = re.finditer(r'[A-Z]{2,}', input_string)
  for match in acronym_matches:
    acronym = match.group()
    start, end = match.span()
    # If this match ends the input string, the last char won't begin a new word.
    # e.g. IOFunc -> io_func but FuncIO -> func_io
    if match.end() != len(input_string):
      acronym = acronym[:-1]
      end -= 1
    input_string = acronym.capitalize().join(
        (input_string[:start], input_string[end:]))
  return camel_to_snake_case(input_string)
