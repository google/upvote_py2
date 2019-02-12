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

import os
import mock

from common import context
from upvote.gae.datastore.models import singleton
from upvote.gae.lib.bit9 import utils as bit9_utils
from upvote.gae.lib.testing import basetest
from absl.testing import absltest


class Bit9TestCase(basetest.UpvoteTestCase):

  def setUp(self, **kwargs):

    super(Bit9TestCase, self).setUp(**kwargs)

    # Set up a fake Bit9ApiAuth entity in Datastore.
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = os.path.join(
        absltest.get_default_test_srcdir(),
        'upvote/gae/lib/bit9',
        'fake_credentials.json')
    self.Patch(
        bit9_utils.singleton.kms_ndb.EncryptedBlobProperty, '_Encrypt',
        return_value='blah')
    self.Patch(
        bit9_utils.singleton.kms_ndb.EncryptedBlobProperty, '_Decrypt',
        return_value='blah')
    singleton.Bit9ApiAuth.SetInstance(api_key='blah')

    self.mock_ctx = mock.Mock(spec=bit9_utils.api.Context)
    self.Patch(
        bit9_utils.api, 'Context', return_value=self.mock_ctx)

  def tearDown(self):

    super(Bit9TestCase, self).tearDown()

    # We have to reset the LazyProxy in utils, otherwise utils.CONTEXT will
    # cache the mock context and break subsequent tests.
    context.ResetLazyProxies()

  def PatchApiRequests(self, *results):
    requests = []
    for batch in results:
      if isinstance(batch, list):
        requests.append([obj.to_raw_dict() for obj in batch])
      else:
        requests.append(batch.to_raw_dict())
    self.mock_ctx.ExecuteRequest.side_effect = requests
