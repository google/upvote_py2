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

"""Unit tests for rule.py."""

from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import rule as rule_models
from upvote.gae.lib.testing import basetest
from upvote.shared import constants


class RuleTest(basetest.UpvoteTestCase):

  def testInsertBigQueryRow_LocalRule_UserKeyMissing(self):
    """Verifies that a LOCAL row is inserted, even if user_key is missing.

    The host_id and user_key columns have to be NULLABLE in order to support
    GLOBAL rows (which will lack values for both of these columns). If user_key
    is mistakenly omitted, we should still insert a LOCAL row with the values
    we have.
    """
    blockable_key = test_utils.CreateSantaBlockable().key
    local_rule = test_utils.CreateSantaRule(blockable_key, host_id='12345')
    local_rule.InsertBigQueryRow()

    self.assertBigQueryInsertions(
        [constants.BIGQUERY_TABLE.RULE], reset_mock=False)

    calls = self.GetBigQueryCalls()
    self.assertLen(calls, 1)
    self.assertEqual(constants.RULE_SCOPE.LOCAL, calls[0][1].get('scope'))

  def testInsertBigQueryRow_LocalRule_HostIdMissing(self):
    """Verifies that a LOCAL row is inserted, even if host_id is missing.

    The host_id and user_key columns have to be NULLABLE in order to support
    GLOBAL rows (which will lack values for both of these columns). If host_id
    is mistakenly omitted, we should still insert a LOCAL row with the values
    we have.
    """
    blockable_key = test_utils.CreateSantaBlockable().key
    user_key = test_utils.CreateUser().key
    local_rule = test_utils.CreateSantaRule(blockable_key, user_key=user_key)
    local_rule.InsertBigQueryRow()

    self.assertBigQueryInsertions(
        [constants.BIGQUERY_TABLE.RULE], reset_mock=False)

    calls = self.GetBigQueryCalls()
    self.assertLen(calls, 1)
    self.assertEqual(constants.RULE_SCOPE.LOCAL, calls[0][1].get('scope'))

  def testInsertBigQueryRow_GlobalRule(self):

    blockable_key = test_utils.CreateSantaBlockable().key
    global_rule = test_utils.CreateSantaRule(blockable_key)
    global_rule.InsertBigQueryRow()

    self.assertBigQueryInsertions(
        [constants.BIGQUERY_TABLE.RULE], reset_mock=False)

    calls = self.GetBigQueryCalls()
    self.assertLen(calls, 1)
    self.assertEqual(constants.RULE_SCOPE.GLOBAL, calls[0][1].get('scope'))


class RuleChangeSetTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(RuleChangeSetTest, self).setUp()
    self.bit9_binary = test_utils.CreateBit9Binary()

  def testBlockableKey(self):
    change = rule_models.RuleChangeSet(
        rule_keys=[],
        change_type=constants.RULE_POLICY.WHITELIST,
        parent=self.bit9_binary.key)
    change.put()

    self.assertEqual(self.bit9_binary.key, change.blockable_key)

  def testBlockableKey_NoParent(self):
    change = rule_models.RuleChangeSet(
        rule_keys=[],
        change_type=constants.RULE_POLICY.WHITELIST,
        parent=None)
    with self.assertRaises(ValueError):
      change.put()

  def testBlockableKey_NotABlockableKey(self):
    host = test_utils.CreateBit9Host()
    change = rule_models.RuleChangeSet(
        rule_keys=[],
        change_type=constants.RULE_POLICY.WHITELIST,
        parent=host.key)
    with self.assertRaises(ValueError):
      change.put()


if __name__ == '__main__':
  basetest.main()
