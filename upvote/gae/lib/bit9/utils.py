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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import re

from common import context

from upvote.gae.datastore.models import bit9
from upvote.gae.lib.bit9 import constants as bit9_constants
from upvote.gae.lib.bit9 import api  # pylint: disable=g-line-too-long
from upvote.gae.shared.common import settings


_NORMAL_USER_REGEX = re.compile(
    settings.AD_DOMAIN + r'\\([a-zA-Z\.-_]+)')
_USER_REGEXES = [_NORMAL_USER_REGEX]


def camel_to_snake_case(input_string):  # pylint: disable=g-bad-name
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


def camel_to_snake_case_with_acronyms(input_string):  # pylint: disable=g-bad-name
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


def ExpandHostname(bit9_hostname):
  """Add the AD hostname suffix if the provided one isn't fully-qualified."""
  bit9_hostname = bit9_hostname.lower()

  if '.' in bit9_hostname:
    return bit9_hostname
  return '.'.join((bit9_hostname, settings.AD_HOSTNAME.lower()))


@context.LazyProxy
def CONTEXT():  # pylint: disable=g-bad-name
  api_key = bit9.Bit9ApiAuth.GetInstance().api_key
  return api.Context(settings.ENV.BIT9_REST_URL, api_key, 30)


def StripDownLevelDomain(name):
  r"""Strip the domain from a windows down-level logon name.

  Args:
    name: str, Down-level logon name. Example: 'DOMAIN\userhost'.

  Returns:
    'NOTDOMAIN\user' or 'user' if domain matches the AD_DOMAIN constant.
  """
  domain, _, path = name.partition('\\')
  return path if domain.lower() == settings.AD_DOMAIN.lower() else name


def ExtractHostUser(host_user_str):
  r"""Extract the host user from the Bit9 string.

  Args:
    host_user_str: str, The user string returned by Bit9.

  Returns:
    The Google username or, if that isn't found, the domain\user string found in
    the provided host user string.
    If the string represents a computer account , an empty string is returned.
  """
  # The computer account is not considered a user.
  if host_user_str.endswith('$'):
    return ''

  for regex in _USER_REGEXES:
    match = regex.match(host_user_str)
    if match is not None:
      return match.group(1).lower()
  return host_user_str


def ExtractHostUsers(host_users_str):
  r"""Extract host users string from Bit9 into the component users.

  Args:
    host_users_str: str, The comma-separated list of host users given by Bit9.
        e.g. "DOMAIN\userfoo,DOMAIN\userfoo2,HOST\computerfoo$"

  Returns:
    A list of Google usernames (if they could be extracted) and normal
    domain\user strings found in the host user string.
    Computer accounts are filtered out
  """
  pieces = host_users_str.split(',') if host_users_str else []
  extracted = (ExtractHostUser(piece) for piece in pieces)
  return sorted(list(set(filter(None, extracted))))


def GetEffectiveInstallerState(file_flags):
  marked_yes = file_flags & bit9_constants.FileFlags.MARKED_INSTALLER
  marked_no = file_flags & bit9_constants.FileFlags.MARKED_NOT_INSTALLER
  detected = file_flags & bit9_constants.FileFlags.DETECTED_INSTALLER
  return bool(marked_yes or (detected and not marked_no))
