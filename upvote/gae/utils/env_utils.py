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

"""Environment-related utility methods."""

import logging
import os

from upvote.gae import settings
from upvote.gae.utils import settings_utils


def _IsRunningInEnvironment(expected_env):
  """Determines if the app is running in the given environment."""
  try:
    return settings.ENV.NAME == expected_env.NAME
  except settings_utils.UnknownEnvironmentError:
    return False


def RunningInProd():
  return _IsRunningInEnvironment(settings.ProdEnv)


def RunningLocally():
  is_local = os.environ.get('SERVER_SOFTWARE', '').startswith('Development')
  verb = 'is' if is_local else 'is not'
  logging.info('Application environment %s local', verb)
  return is_local
