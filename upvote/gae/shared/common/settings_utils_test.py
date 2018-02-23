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

"""Tests for common settings."""

import os

from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import settings
from upvote.gae.shared.common import settings_utils


class CurrentEnvironmentTest(basetest.UpvoteTestCase):

  def testHostnameCheck(self):
    os.environ['DEFAULT_VERSION_HOSTNAME'] = settings.ProdEnv.HOSTNAME
    self.assertEqual(settings.ProdEnv, settings_utils.CurrentEnvironment())

  def testHostnameCheck_Unknown(self):
    os.environ['DEFAULT_VERSION_HOSTNAME'] = 'something_else'
    with self.assertRaises(settings_utils.UnknownEnvironment):
      settings_utils.CurrentEnvironment()

  def testAppIdCheck(self):
    os.environ['APPLICATION_ID'] = settings.ProdEnv.PROJECT_ID
    self.assertEqual(settings.ProdEnv, settings_utils.CurrentEnvironment())

    os.environ['APPLICATION_ID'] = 'something_else'
    with self.assertRaises(settings_utils.UnknownEnvironment):
      settings_utils.CurrentEnvironment()

  def testUnknown(self):
    with self.assertRaises(settings_utils.UnknownEnvironment):
      settings_utils.CurrentEnvironment()


if __name__ == '__main__':
  basetest.main()
