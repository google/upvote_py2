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

from absl.testing import absltest
from upvote.gae.modules.bit9_api.api import utils


class UtilsTest(absltest.TestCase):

  def testToAsciiStr(self):
    tests = [
        (u'Mircosoft\u00A9', 'Mircosoft'),
        (u'I like cents\xA2', 'I like cents'),
        ('I like cents\xA2', 'I like cents'),
        ('Hello\nthere', 'Hello there'),
        ('\nHello\nthere\n\n\n', 'Hello there'),
        (u'Nice string', 'Nice string'),
        ('Nicer string', 'Nicer string'),
        (u'foo\nbar', 'foo bar'),
        (None, '')
    ]

    for (str_input, str_output) in tests:
      ret = utils.to_ascii_str(str_input)
      self.assertEqual(str_output, ret)
    self.assertRaises(TypeError, utils.to_ascii_str, ['hello'])

  def testConvertSomeCamelCases(self):
    tests = (
        ('thisIsCamelCase', 'this_is_camel_case'),
        ('this_isPartiallyCamelCase', 'this_is_partially_camel_case'),
        ('this_is_snake_case', 'this_is_snake_case'))
    for test, expected in tests:
      self.assertEqual(expected, utils.camel_to_snake_case(test))

  def testCamelToSnakeCaseWithAcronyms(self):
    tests = (
        ('ACamelCase', 'a_camel_case'),
        ('AFOCamelCase', 'afo_camel_case'),
        ('CamelAFOCase', 'camel_afo_case'),
        ('CamelCaseAFO', 'camel_case_afo'))
    for test, expected in tests:
      self.assertEqual(expected, utils.camel_to_snake_case_with_acronyms(test))


if __name__ == '__main__':
  absltest.main()
