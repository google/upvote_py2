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

"""Unit tests for appengine_config.py."""

from upvote.gae import settings
from upvote.gae.datastore.models import rule as rule_models
from upvote.gae.datastore.models import santa as santa_models
from upvote.gae.lib.testing import basetest
from upvote.shared import constants


# Done for the sake of brevity.
_TABLE = constants.BIGQUERY_TABLE


class AppEngineConfigTest(basetest.UpvoteTestCase):

  def testCriticalRuleCreation(self):
    # pylint: disable=g-import-not-at-top,unused-import,unused-variable
    from upvote.gae import appengine_config

    expected_count = len(settings.CRITICAL_RULES)
    self.assertEntityCount(santa_models.SantaCertificate, expected_count)
    self.assertEntityCount(rule_models.SantaRule, expected_count)
    self.assertBigQueryInsertions(
        [_TABLE.CERTIFICATE, _TABLE.RULE] * expected_count)


if __name__ == '__main__':
  basetest.main()
