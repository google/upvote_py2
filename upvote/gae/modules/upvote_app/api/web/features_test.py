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

"""Unit tests for feature handlers."""

import httplib
import mock
import webapp2

from google.appengine.api import memcache

from upvote.gae.datastore import test_utils
from upvote.gae.lib.testing import basetest
from upvote.gae.modules.upvote_app.api.web import features
from upvote.gae.utils import group_utils


class FeatureHandlerTest(basetest.UpvoteTestCase):

  ROUTE = '/features/%s'

  def setUp(self):

    app = webapp2.WSGIApplication(routes=[features.ROUTES])
    super(FeatureHandlerTest, self).setUp(wsgi_app=app)

    # Patch out the _SUPPORTED_FEATURES constant.
    supported_features = {'valid': ['group1', 'group2']}
    patcher = mock.patch.dict(
        features.__dict__, values={'_SUPPORTED_FEATURES': supported_features})
    self.addCleanup(patcher.stop)
    patcher.start()

    # Patch out the GroupManager for all tests.
    self.mock_group_manager = mock.Mock(spec=group_utils.GroupManager)
    self.Patch(
        features.group_utils, 'GroupManager',
        return_value=self.mock_group_manager)

  def testGet_UnknownFeature(self):
    with self.LoggedInUser():
      self.testapp.get(self.ROUTE % 'invalid', status=httplib.FORBIDDEN)

  def testGet_UnknownGroup(self):
    self.mock_group_manager.DoesGroupExist.return_value = False
    with self.LoggedInUser():
      self.testapp.get(self.ROUTE % 'valid', status=httplib.FORBIDDEN)

  def testGet_UnexpectedException(self):
    self.mock_group_manager.DoesGroupExist.side_effect = Exception
    with self.LoggedInUser():
      self.testapp.get(self.ROUTE % 'valid', status=httplib.FORBIDDEN)

  def testGet_MemcacheMiss_Approved(self):

    self.mock_group_manager.DoesGroupExist.side_effect = [True, True]
    self.mock_group_manager.AllMembers.side_effect = [['aaa', 'bbb'], ['ccc']]
    self.assertMemcacheLacks('feature_valid')

    user = test_utils.CreateUser(email='ccc@blah.blah')
    with self.LoggedInUser(user=user):
      self.testapp.get(self.ROUTE % 'valid', status=httplib.OK)

    self.assertEqual(2, self.mock_group_manager.DoesGroupExist.call_count)
    self.assertEqual(2, self.mock_group_manager.AllMembers.call_count)
    self.assertMemcacheContains('feature_valid', 'aaa,bbb,ccc')

  def testGet_MemcacheMiss_Unapproved(self):

    self.mock_group_manager.DoesGroupExist.side_effect = [True, True]
    self.mock_group_manager.AllMembers.side_effect = [['aaa', 'bbb'], ['ccc']]
    self.assertMemcacheLacks('feature_valid')

    user = test_utils.CreateUser(email='ddd@blah.blah')
    with self.LoggedInUser(user=user):
      self.testapp.get(self.ROUTE % 'valid', status=httplib.FORBIDDEN)

    self.assertEqual(2, self.mock_group_manager.DoesGroupExist.call_count)
    self.assertEqual(2, self.mock_group_manager.AllMembers.call_count)
    self.assertMemcacheContains('feature_valid', 'aaa,bbb,ccc')

  def testGet_MemcacheHit_Approved(self):

    memcache.set('feature_valid', 'aaa,bbb,ccc')

    user = test_utils.CreateUser(email='ccc@blah.blah')
    with self.LoggedInUser(user=user):
      self.testapp.get(self.ROUTE % 'valid', status=httplib.OK)

    self.mock_group_manager.DoesGroupExist.assert_not_called()
    self.mock_group_manager.AllMembers.assert_not_called()
    self.assertMemcacheContains('feature_valid', 'aaa,bbb,ccc')

  def testGet_MemcacheHit_Unapproved(self):

    memcache.set('feature_valid', 'aaa,bbb,ccc')

    user = test_utils.CreateUser(email='ddd@blah.blah')
    with self.LoggedInUser(user=user):
      self.testapp.get(self.ROUTE % 'valid', status=httplib.FORBIDDEN)

    self.mock_group_manager.DoesGroupExist.assert_not_called()
    self.mock_group_manager.AllMembers.assert_not_called()
    self.assertMemcacheContains('feature_valid', 'aaa,bbb,ccc')


if __name__ == '__main__':
  basetest.main()
