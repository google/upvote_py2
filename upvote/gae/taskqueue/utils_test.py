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

"""Tests for taskqueue_utils."""

from google.appengine.ext import deferred

from upvote.gae.lib.testing import basetest
from upvote.gae.taskqueue import utils
from upvote.shared import constants


class QueueSizeTest(basetest.UpvoteTestCase):

  def testSuccess(self):
    self.assertEqual(0, utils.QueueSize())
    expected_size = 10
    for _ in xrange(expected_size):
      deferred.defer(dir)
    self.assertEqual(expected_size, utils.QueueSize())


class CappedDeferTest(basetest.UpvoteTestCase):

  def testSuccess(self):

    max_size = 6
    total_size = 10

    expected_results = [True] * max_size + [False] * (total_size - max_size)
    actual_results = [
        utils.CappedDefer(dir, max_size) for _ in xrange(total_size)
    ]

    self.assertEqual(expected_results, actual_results)


_DEFAULT = constants.TASK_QUEUE.DEFAULT
_METRICS = constants.TASK_QUEUE.METRICS


def _FreeFunction(a=0):
  return a + 1


if __name__ == '__main__':
  basetest.main()
