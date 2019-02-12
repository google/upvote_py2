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

"""Unit tests for singleton.py."""

import mock

from google.appengine.ext import ndb

from upvote.gae.datastore.models import singleton
from upvote.gae.lib.testing import basetest


class SingletonTest(basetest.UpvoteTestCase):

  def testGetAndSet(self):

    class A(singleton.Singleton):
      a = ndb.StringProperty()

    self.assertIsNone(A.GetInstance())

    inst = A.SetInstance(a='abcd')
    self.assertEqual('abcd', inst.a)

    inst = A.GetInstance()
    self.assertEqual('abcd', inst.a)
    self.assertEqual('A', A.GetInstance().key.id())

  def testOverrideGetId(self):

    class A(singleton.Singleton):
      a = ndb.StringProperty()

      @classmethod
      def _GetId(cls):
        return '1'

    inst = A.SetInstance(a='abcd')
    self.assertEqual('1', inst.key.id())


class SiteXsrfSecretTest(basetest.UpvoteTestCase):

  @mock.patch.object(singleton.os, 'urandom', return_value='foo'*4)
  def testNewXsrfSecret(self, mock_urandom):
    singleton.SiteXsrfSecret.GetInstance().key.delete()
    self.assertEqual('foofoofoofoo', singleton.SiteXsrfSecret.GetSecret())


if __name__ == '__main__':
  basetest.main()
