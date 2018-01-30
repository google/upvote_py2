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

"""Tests for utils."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest
from upvote.shared import utils


class UtilsTest(absltest.TestCase):

  def testConvertSomeCamelCases(self):
    tests = (
        ('thisIsCamelCase', 'this_is_camel_case'),
        ('this_isPartiallyCamelCase', 'this_is_partially_camel_case'),
        ('this_is_snake_case', 'this_is_snake_case'))
    for test, expected in tests:
      self.assertEqual(expected, utils.CamelToSnakeCase(test))


if __name__ == '__main__':
  absltest.main()
