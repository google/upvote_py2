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

"""Tests for memcache_utils."""

import mock

from common.testing import basetest

from upvote.gae.utils import memcache_utils


class MemcacheUtilsTest(basetest.AppEngineTestCase):

  def setUp(self):
    super(MemcacheUtilsTest, self).setUp()

    self.call_mock = mock.Mock(return_value=1)

  def testNoPredicate(self):

    @memcache_utils.ConditionallyCached()
    def foo():
      return self.call_mock()

    foo()
    foo()

    # No cache predicate reverts to normal caching behavior.
    self.assertEqual(1, self.call_mock.call_count)

  def testPredicate(self):
    cache_truthy_args = lambda a, k, r: a[0]

    @memcache_utils.ConditionallyCached(cache_predicate=cache_truthy_args)
    def foo(a):
      return self.call_mock(a)

    foo(True)  # Cached.
    foo(False)  # Not cached.

    foo(False)  # Cache miss.
    foo(True)  # Cache hit.

    # Only the one cache hit will avoid calling through to the mock.
    self.assertEqual(3, self.call_mock.call_count)

  def testDeleteCache(self):

    @memcache_utils.ConditionallyCached()
    def foo():
      return self.call_mock()

    foo()
    foo.DeleteCache()

    foo()

    # Both calls should call through because of the interstitial cache deletion.
    self.assertEqual(2, self.call_mock.call_count)

  def testPassThroughKwargs(self):
    # Only cache if return is truthy and only cache to a single memcache entry.
    @memcache_utils.ConditionallyCached(
        cache_predicate=lambda a, k, r: r, create_key_func=lambda *a: 'const')
    def foo(a='a'):
      return self.call_mock(a)

    self.assertTrue(foo())  # Truthy return so cache value.
    foo(a='b')  # Cache hit even though args differ.

    self.assertEqual(1, self.call_mock.call_count)


if __name__ == '__main__':
  basetest.main()
