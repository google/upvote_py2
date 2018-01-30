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

"""Unit tests for bit9_utils.py."""

import datetime
import mock

from absl.testing import absltest

from upvote.shared import time_utils


class TimeUtilsTest(absltest.TestCase):

  @mock.patch.object(time_utils, 'Now')
  def testTimeRemains(self, mock_now):

    mock_now.side_effect = [
        datetime.datetime(2017, 1, 1, 1, 1, s) for s in xrange(3)]
    start_time = datetime.datetime(2017, 1, 1, 1, 1, 0)
    delta = datetime.timedelta(seconds=1)

    self.assertTrue(time_utils.TimeRemains(start_time, delta))
    self.assertFalse(time_utils.TimeRemains(start_time, delta))
    self.assertFalse(time_utils.TimeRemains(start_time, delta))

  def testDatetimeToInt(self):
    expected = 1000000000
    actual = time_utils.DatetimeToInt(datetime.datetime(2001, 9, 9, 1, 46, 40))
    self.assertEqual(expected, actual)

  def testIntToDatetime(self):
    expected = datetime.datetime(2001, 9, 9, 1, 46, 40)
    actual = time_utils.IntToDatetime(1000000000)
    self.assertEqual(expected, actual)


if __name__ == '__main__':
  absltest.main()
