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

"""Tests for rest_utils."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest
from upvote.gae.modules.bit9_api import constants as bit9_constants
from upvote.gae.modules.bit9_api import rest_utils

from upvote.gae.shared.common import settings


class RestUtilsTest(absltest.TestCase):

  def testStripDownLevelDomain(self):
    self.assertEqual(
        'user',
        rest_utils.StripDownLevelDomain(r'{}\user'.format(settings.AD_DOMAIN)))
    self.assertEqual(
        r'BADDOMAIN\user', rest_utils.StripDownLevelDomain(r'BADDOMAIN\user'))

  def testExtractHostUsers_Empty(self):
    self.assertEqual([], rest_utils.ExtractHostUsers(''))

  def testExtractHostUsers_None(self):
    self.assertEqual([], rest_utils.ExtractHostUsers(None))

  def testExtractHostUsers_Success(self):
    user_str = r'HOST\user,{}\user'.format(settings.AD_DOMAIN)
    expected = [r'HOST\user', r'user']
    actual = rest_utils.ExtractHostUsers(user_str)
    self.assertEqual(expected, actual)

  def testExtractHostUsers_Skip(self):
    user_str = r'HOST\user,{0}\user,HOST\skipuser$,{0}\skipuser$'.format(
        settings.AD_DOMAIN)
    expected = [r'HOST\user', r'user']
    actual = rest_utils.ExtractHostUsers(user_str)
    self.assertEqual(expected, actual)

  def testExtractHostUsers_Dedupe(self):
    user_str = r'HOST\user,{0}\user,HOST\user,{0}\user'.format(
        settings.AD_DOMAIN)
    expected = [r'HOST\user', r'user']
    actual = rest_utils.ExtractHostUsers(user_str)
    self.assertEqual(expected, actual)

  def testExtractHostUsers_MixedCase(self):
    user_str = r'HOST\user,{0}\USer'.format(settings.AD_DOMAIN)
    expected = [r'HOST\user', r'user']
    actual = rest_utils.ExtractHostUsers(user_str)
    self.assertEqual(expected, actual)

  def testGetEffectiveInstallerState_NotDetected_Marked(self):
    flags = bit9_constants.FileFlags.MARKED_INSTALLER
    self.assertTrue(rest_utils.GetEffectiveInstallerState(flags))

  def testGetEffectiveInstallerState_Detected_MarkedNot(self):
    flags = (
        bit9_constants.FileFlags.DETECTED_INSTALLER |
        bit9_constants.FileFlags.MARKED_NOT_INSTALLER)
    self.assertFalse(rest_utils.GetEffectiveInstallerState(flags))

  def testGetEffectiveInstallerState_Detected(self):
    flags = bit9_constants.FileFlags.DETECTED_INSTALLER
    self.assertTrue(rest_utils.GetEffectiveInstallerState(flags))

if __name__ == '__main__':
  absltest.main()
