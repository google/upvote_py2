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

"""Unit tests for mixin.py."""

from google.appengine.ext import ndb

from upvote.gae.datastore.models import mixin
from upvote.gae.lib.testing import basetest


class TestModel(mixin.Base, ndb.Model):
  int_prop = ndb.IntegerProperty()


class TestPlatformModel(mixin.Base, ndb.Model):
  int_prop = ndb.IntegerProperty()

  def GetPlatformName(self):
    return 'some_platform'


class BaseMixinTest(basetest.UpvoteTestCase):

  def testToDict_Put(self):
    test_model = TestModel(int_prop=111)
    test_model.put()
    expected = {
        'int_prop': 111,
        'id': test_model.key.id(),
        'key': test_model.key.urlsafe()}
    self.assertDictEqual(expected, test_model.to_dict())

  def testToDict_NotPut(self):
    test_model = TestModel(int_prop=111)
    expected = {'int_prop': 111}
    self.assertDictEqual(expected, test_model.to_dict())

  def testToDict_WithPlatformName(self):
    test_model = TestPlatformModel(int_prop=111)
    expected = {
        'int_prop': 111,
        'operating_system_family': 'some_platform'}
    self.assertDictEqual(expected, test_model.to_dict())

  def testToDict_ExcludeId(self):

    # Verify that the ID shows up without 'exclude'.
    test_model = TestModel(int_prop=111)
    test_model.put()
    expected = {
        'int_prop': 111,
        'id': test_model.key.id(),
        'key': test_model.key.urlsafe()}
    self.assertDictEqual(expected, test_model.to_dict())

    # Verify that the ID shows up with an irrelevant 'exclude'.
    test_model = TestModel(int_prop=111)
    test_model.put()
    expected = {
        'int_prop': 111,
        'id': test_model.key.id(),
        'key': test_model.key.urlsafe()}
    self.assertDictEqual(expected, test_model.to_dict(exclude=['blah']))

    # Now verify that it doesn't with 'exclude'.
    test_model = TestModel(int_prop=111)
    test_model.put()
    expected = {'int_prop': 111}
    self.assertDictEqual(expected, test_model.to_dict(exclude=['id']))

  def testToDict_ExcludePlatformName(self):
    test_model = TestPlatformModel(int_prop=111)
    expected = {'int_prop': 111}
    self.assertDictEqual(expected, test_model.to_dict(
        exclude=['operating_system_family']))


if __name__ == '__main__':
  basetest.main()
