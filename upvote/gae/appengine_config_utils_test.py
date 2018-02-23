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

"""Tests for appengine_config_utils.py."""

from upvote.gae import appengine_config_utils
from upvote.gae.datastore.models import base
from upvote.gae.datastore.models import bit9
from upvote.gae.datastore.models import santa
from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import settings


class EnsureCriticalRulesTest(basetest.UpvoteTestCase):

  def testSuccess(self):

    self.assertEntityCount(santa.SantaCertificate, 0)
    self.assertEntityCount(santa.SantaRule, 0)

    appengine_config_utils.EnsureCritialRules()
    expected_count = len(settings.CRITICAL_MAC_OS_CERT_HASHES)

    self.assertEntityCount(santa.SantaCertificate, expected_count)
    self.assertEntityCount(santa.SantaRule, expected_count)


class CreateTestEntitiesTest(basetest.UpvoteTestCase):

  def testProd(self):

    self.Patch(
        appengine_config_utils.utils, 'RunningLocally', return_value=False)

    model_classes = [
        base.User, santa.SantaHost, santa.SantaBlockable,
        santa.SantaEvent, bit9.Bit9Host, bit9.Bit9Binary, bit9.Bit9Event]

    for model_class in model_classes:
      self.assertNoEntitiesExist(model_class)

    with self.assertRaises(appengine_config_utils.NotRunningLocally):
      appengine_config_utils.CreateTestEntities('nobody@foo.com')

    for model_class in model_classes:
      self.assertNoEntitiesExist(model_class)

  def testLocal(self):

    self.Patch(
        appengine_config_utils.utils, 'RunningLocally', return_value=True)

    model_classes = [
        base.User, santa.SantaHost, santa.SantaBlockable,
        santa.SantaEvent, bit9.Bit9Host, bit9.Bit9Binary, bit9.Bit9Event]

    for model_class in model_classes:
      self.assertNoEntitiesExist(model_class)

    appengine_config_utils.CreateTestEntities('nobody@foo.com')

    for model_class in model_classes:
      self.assertEntitiesExist(model_class)


if __name__ == '__main__':
  basetest.main()
