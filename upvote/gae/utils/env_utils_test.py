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

"""Unit tests for env_utils.py."""

import os

from common.testing import basetest

from upvote.gae.utils import env_utils


class EnvUtilsTest(basetest.AppEngineTestCase):

  def testRunningLocally(self):

    os.environ['SERVER_SOFTWARE'] = 'Google App Engine/whatever'
    self.assertFalse(env_utils.RunningLocally())

    os.environ['SERVER_SOFTWARE'] = 'Development/whatever'
    self.assertTrue(env_utils.RunningLocally())


if __name__ == '__main__':
  basetest.main()
