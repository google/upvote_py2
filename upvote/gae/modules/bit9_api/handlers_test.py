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

"""Unit tests for handlers.py."""

import httplib
import json
import mock
import webapp2

from google.appengine.ext import ndb

from upvote.gae.modules.bit9_api import change_set
from upvote.gae.modules.bit9_api import constants as bit9_constants
from upvote.gae.modules.bit9_api import handlers
from upvote.gae.modules.bit9_api import utils
from upvote.gae.modules.bit9_api.api import api
from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import settings
from upvote.gae.shared.models import bit9 as bit9_db
from upvote.gae.shared.models import test_utils
from upvote.shared import constants

_HOST_HEALTH_PROPS = bit9_constants.UpvoteHostHealthProperties


class HandlerTest(basetest.UpvoteTestCase):

  def setUp(self, **kwargs):
    super(HandlerTest, self).setUp(**kwargs)
    self.Patch(utils, 'CONTEXT')

  def _PatchApiRequests(self, *results):
    requests = []
    for batch in results:
      if isinstance(batch, list):
        requests.append([obj.to_raw_dict() for obj in batch])
      else:
        requests.append(batch.to_raw_dict())
    utils.CONTEXT.ExecuteRequest.side_effect = requests


class CommitBlockableChangeSetTest(HandlerTest):

  def setUp(self):
    app = webapp2.WSGIApplication([
        webapp2.Route(
            '/<blockable_id>',
            handler=handlers.CommitBlockableChangeSet)])
    super(CommitBlockableChangeSetTest, self).setUp(wsgi_app=app)

    self.binary = test_utils.CreateBit9Binary()
    self.change = test_utils.CreateRuleChangeSet(self.binary.key)

  def testCommit(self):
    with mock.patch.object(change_set, 'CommitChangeSet') as mock_commit:
      self.testapp.get('/%s' % self.binary.key.id())

      self.RunDeferredTasks(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE)
      mock_commit.assert_called_once_with(self.change.key)

  def testCommit_UnknownBlockable(self):
    self.testapp.get('/notablockable', status=httplib.NOT_FOUND)

  def testCommit_BadPlatform(self):
    santa_blockable = test_utils.CreateSantaBlockable()
    self.testapp.get(
        '/%s' % santa_blockable.key.id(), status=httplib.BAD_REQUEST)


class GetHostHealthInformationTest(HandlerTest):

  def setUp(self):
    app = webapp2.WSGIApplication(
        [('/somerequest', handlers.GetHostHealthInformation)])
    super(GetHostHealthInformationTest, self).setUp(wsgi_app=app)

  def testSuccess(self):
    computer = api.Computer(
        name='fake_name',
        connected=True,
        agent_version='v1',
        last_register_date=u'2014-05-02T09:01:01Z',
        has_health_check_errors=False,
        policy_name='fake_policy',
        agent_cache_size=16,
        initializing=True,
        init_percent=100)
    self._PatchApiRequests(computer)

    response = self.testapp.get('/somerequest', {'host_id': 12345})
    response_dict = json.loads(response.body)

    self.assertEqual('fake_name', response_dict[_HOST_HEALTH_PROPS.NAME])
    self.assertEqual(True, response_dict[_HOST_HEALTH_PROPS.CONNECTED])
    self.assertEqual(
        u'2014-05-02T09:01:01Z',
        response_dict[_HOST_HEALTH_PROPS.LAST_REGISTER_DATE])
    self.assertEqual('v1', response_dict[_HOST_HEALTH_PROPS.AGENT_VERSION])
    self.assertEqual(
        False, response_dict[_HOST_HEALTH_PROPS.HAS_HEALTH_CHECK_ERRORS])
    self.assertEqual(
        'fake_policy', response_dict[_HOST_HEALTH_PROPS.POLICY_NAME])
    self.assertEqual(16, response_dict[_HOST_HEALTH_PROPS.AGENT_CACHE_SIZE])
    self.assertEqual(True, response_dict[_HOST_HEALTH_PROPS.IS_INITIALIZING])

  def testNoHostId(self):
    self.testapp.get('/somerequest', {}, status=httplib.BAD_REQUEST)

  def testMemoization(self):
    computer = api.Computer(
        name='fake_name',
        connected=True,
        agent_version='v1',
        last_register_date=u'2014-05-02T09:01:01Z',
        has_health_check_errors=False,
        policy_name='fake_policy',
        agent_cache_size=16,
        initializing=False,
        init_percent=100)
    self._PatchApiRequests(computer)

    self.testapp.get('/somerequest', {'host_id': 12345})
    self.testapp.get('/somerequest', {'host_id': 12345})

    self.assertEqual(1, utils.CONTEXT.ExecuteRequest.call_count)


class AssociatedHostsTest(HandlerTest):

  def setUp(self):
    app = webapp2.WSGIApplication(
        [('/(.*)', handlers.AssociatedHosts)])
    super(AssociatedHostsTest, self).setUp(wsgi_app=app)

  def testSuccess(self):
    user = test_utils.CreateUser(
        email='foobar@' + settings.USER_EMAIL_DOMAIN)
    computer = api.Computer(
        id=123, name='foo', policy_id=456,
        users=settings.AD_DOMAIN + '\\foobar')
    self._PatchApiRequests([computer])

    response = self.testapp.get('/%s' % user.key.id())

    self.assertSameElements(['123'], response.json)
    hosts = bit9_db.Bit9Host.query().fetch()
    self.assertEqual(1, len(hosts))
    host = hosts[0]
    self.assertEqual('123', host.key.id())
    self.assertEqual(utils.ExpandHostname('foo'), host.hostname)
    self.assertEqual(ndb.Key(bit9_db.Bit9Policy, '456'), host.policy_key)
    self.assertEqual(['foobar'], host.users)

  def testCacheMultiple(self):
    self._PatchApiRequests([])

    with self.LoggedInUser() as user:
      self.testapp.get('/%s' % user.key.id())
      self.testapp.get('/%s' % user.key.id())

    self.assertEqual(1, utils.CONTEXT.ExecuteRequest.call_count)

  def testUnknownUser(self):
    self.testapp.get('/bar', status=httplib.NOT_FOUND)


if __name__ == '__main__':
  basetest.main()
