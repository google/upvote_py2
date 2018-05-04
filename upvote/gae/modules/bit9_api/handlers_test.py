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
import mock
import webapp2

from upvote.gae.datastore import test_utils
from upvote.gae.modules.bit9_api import change_set
from upvote.gae.modules.bit9_api import constants as bit9_constants
from upvote.gae.modules.bit9_api import handlers
from upvote.gae.modules.bit9_api import utils
from upvote.gae.shared.common import basetest
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


if __name__ == '__main__':
  basetest.main()
