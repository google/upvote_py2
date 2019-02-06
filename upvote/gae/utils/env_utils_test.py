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

from upvote.gae import settings
from upvote.gae.lib.testing import basetest
from upvote.gae.utils import env_utils


class RunningLocallyTest(basetest.UpvoteTestCase):

  def testNotLocal(self):
    os.environ['SERVER_SOFTWARE'] = 'Google App Engine/whatever'
    self.assertFalse(env_utils.RunningLocally())

  def testLocal(self):
    os.environ['SERVER_SOFTWARE'] = 'Development/whatever'
    self.assertTrue(env_utils.RunningLocally())


class CurrentEnvironmentTest(basetest.UpvoteTestCase):

  def testHostnameCheck(self):
    os.environ['DEFAULT_VERSION_HOSTNAME'] = settings.ProdEnv.HOSTNAME
    self.assertEqual(settings.ProdEnv, env_utils.CurrentEnvironment())

  def testHostnameCheck_Unknown(self):
    os.environ['DEFAULT_VERSION_HOSTNAME'] = 'something_else'
    with self.assertRaises(env_utils.UnknownEnvironmentError):
      env_utils.CurrentEnvironment()

  def testAppIdCheck(self):
    os.environ['APPLICATION_ID'] = settings.ProdEnv.PROJECT_ID
    self.assertEqual(settings.ProdEnv, env_utils.CurrentEnvironment())

    os.environ['APPLICATION_ID'] = 'something_else'
    with self.assertRaises(env_utils.UnknownEnvironmentError):
      env_utils.CurrentEnvironment()

  def testUnknown(self):
    with self.assertRaises(env_utils.UnknownEnvironmentError):
      env_utils.CurrentEnvironment()


if __name__ == '__main__':
  basetest.main()
