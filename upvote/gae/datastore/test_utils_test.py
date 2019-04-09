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

"""Tests for test_utils.py."""

from upvote.gae import settings
from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import binary as binary_models
from upvote.gae.datastore.models import event as event_models
from upvote.gae.datastore.models import host as host_models
from upvote.gae.datastore.models import user
from upvote.gae.lib.testing import basetest


class CreateTestEntitiesTest(basetest.UpvoteTestCase):

  def testProd(self):

    self.Patch(test_utils.env_utils, 'RunningLocally', return_value=False)

    model_classes = [
        user.User, host_models.SantaHost, binary_models.SantaBlockable,
        event_models.SantaEvent, host_models.Bit9Host, binary_models.Bit9Binary,
        event_models.Bit9Event]

    for model_class in model_classes:
      self.assertNoEntitiesExist(model_class)

    with self.assertRaises(test_utils.NotRunningLocallyError):
      test_utils.CreateTestEntities('nobody@foo.com')

    for model_class in model_classes:
      self.assertNoEntitiesExist(model_class)

  def testLocal(self):

    self.Patch(test_utils.env_utils, 'RunningLocally', return_value=True)
    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=False)

    model_classes = [
        user.User, host_models.SantaHost, binary_models.SantaBlockable,
        event_models.SantaEvent, host_models.Bit9Host, binary_models.Bit9Binary,
        event_models.Bit9Event]

    for model_class in model_classes:
      self.assertNoEntitiesExist(model_class)

    test_utils.CreateTestEntities('nobody@foo.com')

    for model_class in model_classes:
      self.assertEntitiesExist(model_class)


if __name__ == '__main__':
  basetest.main()
