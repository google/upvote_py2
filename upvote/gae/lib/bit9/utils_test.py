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

"""Tests for API utils."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from upvote.gae import settings
from upvote.gae.lib.bit9 import constants as bit9_constants
from upvote.gae.lib.bit9 import utils
from absl.testing import absltest


class CamelToSnakeCaseTest(absltest.TestCase):

  def testConversions(self):
    tests = (
        ('thisIsCamelCase', 'this_is_camel_case'),
        ('this_isPartiallyCamelCase', 'this_is_partially_camel_case'),
        ('this_is_snake_case', 'this_is_snake_case'))
    for test, expected in tests:
      self.assertEqual(expected, utils.camel_to_snake_case(test))


class CamelToSnakeCaseWithAcronymsTest(absltest.TestCase):

  def testConversions(self):
    tests = (
        ('ACamelCase', 'a_camel_case'),
        ('AFOCamelCase', 'afo_camel_case'),
        ('CamelAFOCase', 'camel_afo_case'),
        ('CamelCaseAFO', 'camel_case_afo'))
    for test, expected in tests:
      self.assertEqual(expected, utils.camel_to_snake_case_with_acronyms(test))


class ExpandHostnameTest(absltest.TestCase):

  def testSuccess(self):
    partial_hostname = 'im-a-computer'
    expected = partial_hostname + '.' + settings.AD_HOSTNAME.lower()
    self.assertEqual(expected, utils.ExpandHostname(partial_hostname))

  def testAlreadyFullyQualified(self):
    hostname = 'im-a-computer.' + settings.AD_HOSTNAME.lower()
    self.assertEqual(hostname, utils.ExpandHostname(hostname))


class StripDownLevelDomainTest(absltest.TestCase):

  def testSuccess(self):
    self.assertEqual(
        'user',
        utils.StripDownLevelDomain(r'{}\user'.format(settings.AD_DOMAIN)))
    self.assertEqual(
        r'BADDOMAIN\user', utils.StripDownLevelDomain(r'BADDOMAIN\user'))


class ExtractHostUsersTest(absltest.TestCase):

  def testEmpty(self):
    self.assertEqual([], utils.ExtractHostUsers(''))

  def testNone(self):
    self.assertEqual([], utils.ExtractHostUsers(None))

  def testSuccess(self):
    user_str = r'HOST\user,{}\user'.format(settings.AD_DOMAIN)
    expected = [r'HOST\user', r'user']
    actual = utils.ExtractHostUsers(user_str)
    self.assertEqual(expected, actual)

  def testSkip(self):
    user_str = r'HOST\user,{0}\user,HOST\skipuser$,{0}\skipuser$'.format(
        settings.AD_DOMAIN)
    expected = [r'HOST\user', r'user']
    actual = utils.ExtractHostUsers(user_str)
    self.assertEqual(expected, actual)

  def testDedupe(self):
    user_str = r'HOST\user,{0}\user,HOST\user,{0}\user'.format(
        settings.AD_DOMAIN)
    expected = [r'HOST\user', r'user']
    actual = utils.ExtractHostUsers(user_str)
    self.assertEqual(expected, actual)

  def testMixedCase(self):
    user_str = r'HOST\user,{0}\USer'.format(settings.AD_DOMAIN)
    expected = [r'HOST\user', r'user']
    actual = utils.ExtractHostUsers(user_str)
    self.assertEqual(expected, actual)


class GetEffectiveInstallerStateTest(absltest.TestCase):

  def testNotDetected_Marked(self):
    flags = bit9_constants.FileFlags.MARKED_INSTALLER
    self.assertTrue(utils.GetEffectiveInstallerState(flags))

  def testDetected_MarkedNot(self):
    flags = (
        bit9_constants.FileFlags.DETECTED_INSTALLER |
        bit9_constants.FileFlags.MARKED_NOT_INSTALLER)
    self.assertFalse(utils.GetEffectiveInstallerState(flags))

  def testDetected(self):
    flags = bit9_constants.FileFlags.DETECTED_INSTALLER
    self.assertTrue(utils.GetEffectiveInstallerState(flags))


if __name__ == '__main__':
  absltest.main()
