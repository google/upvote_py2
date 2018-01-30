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

"""Simple reusable utilities."""

import datetime
import itertools
import logging
import os

from upvote.gae.shared.common import settings
from upvote.gae.shared.common import settings_utils


def _IsRunningInEnvironment(expected_env):
  """Determines if the app is running in the given environment."""
  try:
    return settings.ENV.NAME == expected_env.NAME
  except settings_utils.UnknownEnvironment:
    return False


def RunningInProd():  # pylint:disable=invalid-name
  return _IsRunningInEnvironment(settings.ProdEnv)


def RunningLocally():  # pylint:disable=invalid-name
  is_local = os.environ.get('SERVER_SOFTWARE', '').startswith('Development')
  verb = 'is' if is_local else 'is not'
  logging.debug('Application environment %s local', verb)
  return is_local


def Grouper(iterable, chunk_size, fillvalue=None):
  """Chunks an iterable.

  Source: http://docs.python.org/library/itertools.html.

  Args:
    iterable: iterable, An iterable.
    chunk_size: int, Chunk size.
    fillvalue: object, Fill value.

  Returns:
    An iterable of chunks.
  """
  args = [iter(iterable)] * chunk_size
  return itertools.izip_longest(*args, fillvalue=fillvalue)


def ToUtcTimestamp(dt):
  """Returns a datetime's offset from the POSIX epoch in seconds.

  Args:
    dt: The datetime object for which the epoch timestamp will be calculated.

  Returns:
    The number of seconds between the POSIX epoch and the provided datetime.
  """
  return (dt - datetime.datetime.utcfromtimestamp(0)).total_seconds()
