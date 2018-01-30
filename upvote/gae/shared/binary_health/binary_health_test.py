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

"""Unit tests for binary_health.py."""

import mock

from upvote.gae.shared.binary_health import binary_health
from upvote.gae.shared.common import basetest


class PerformLookupTest(basetest.UpvoteTestCase):

  def testPerformLookup_Success(self):

    expected_response_dict = {'some_key': 'some_value'}

    mock_lookup_func = mock.Mock()
    mock_lookup_func.side_effect = [expected_response_dict]
    mock_metric = mock.Mock()

    actual_response_dict = binary_health._PerformLookup(
        'some_service', mock_lookup_func, mock_metric, 'some_hash')

    self.assertDictEqual(expected_response_dict, actual_response_dict)
    self.assertEqual(1, mock_lookup_func.call_count)
    self.assertEqual(1, mock_metric.Success.call_count)
    self.assertEqual(0, mock_metric.Failure.call_count)

  def testPerformLookup_Failure_WithMessage(self):

    expected_error_message = 'OMG WTF'

    mock_lookup_func = mock.Mock()
    mock_lookup_func.side_effect = Exception(expected_error_message)
    mock_metric = mock.Mock()

    self.assertRaises(
        binary_health.LookupFailure, binary_health._PerformLookup,
        'some_service', mock_lookup_func, mock_metric, 'some_hash')

    self.assertEqual(1, mock_lookup_func.call_count)
    self.assertEqual(0, mock_metric.Success.call_count)
    self.assertEqual(1, mock_metric.Failure.call_count)

  def testPerformLookup_Failure_WithoutMessage(self):

    # Quick and dirty way to simulate an Exception without a message.
    bare_exception = Exception()
    delattr(bare_exception, 'message')

    mock_lookup_func = mock.Mock()
    mock_lookup_func.side_effect = bare_exception
    mock_metric = mock.Mock()

    self.assertRaises(
        binary_health.LookupFailure, binary_health._PerformLookup,
        'some_service', mock_lookup_func, mock_metric, 'some_hash')

    self.assertEqual(1, mock_lookup_func.call_count)
    self.assertEqual(0, mock_metric.Success.call_count)
    self.assertEqual(1, mock_metric.Failure.call_count)


if __name__ == '__main__':
  basetest.main()
