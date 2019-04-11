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

"""Tests for RuleChangeSet commitment."""

import datetime

import mock

from google.appengine.ext import deferred
from google.appengine.ext import ndb

from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import rule as rule_models
from upvote.gae.lib.bit9 import api
from upvote.gae.lib.bit9 import change_set
from upvote.gae.lib.bit9 import constants as bit9_constants
from upvote.gae.lib.testing import basetest
from upvote.gae.lib.testing import bit9test
from upvote.shared import constants
from absl.testing import absltest


class ChangeLocalStateTest(bit9test.Bit9TestCase):

  def testNoFileInstances(self):

    binary = test_utils.CreateBit9Binary(file_catalog_id='1111')
    user = test_utils.CreateUser()
    local_rule = test_utils.CreateBit9Rule(
        binary.key, host_id='2222', user_key=user.key,
        policy=constants.RULE_POLICY.WHITELIST, is_fulfilled=False)

    # Simulate getting no fileInstances from Bit9.
    self.PatchApiRequests([])

    change_set.ChangeLocalState(
        binary, local_rule, bit9_constants.APPROVAL_STATE.APPROVED)

    self.assertFalse(local_rule.key.get().is_fulfilled)
    self.assertNoBigQueryInsertions()

  def testNonWhitelist(self):

    binary = test_utils.CreateBit9Binary(file_catalog_id='1111')
    user = test_utils.CreateUser()
    local_rule = test_utils.CreateBit9Rule(
        binary.key, host_id='2222', user_key=user.key,
        policy=constants.RULE_POLICY.FORCE_INSTALLER, is_fulfilled=False)

    # Mock out the Bit9 API interactions.
    file_instance = api.FileInstance(
        id=3333,
        file_catalog_id=1111,
        computer_id=2222,
        local_state=bit9_constants.APPROVAL_STATE.UNAPPROVED)
    self.PatchApiRequests([file_instance], file_instance)

    change_set.ChangeLocalState(
        binary, local_rule, bit9_constants.APPROVAL_STATE.APPROVED)

    # Verify the Bit9 API interactions.
    self.mock_ctx.ExecuteRequest.assert_has_calls([
        mock.call(
            'GET', api_route='fileInstance',
            query_args=[r'q=computerId:2222', 'q=fileCatalogId:1111']),
        mock.call(
            'POST', api_route='fileInstance',
            data={'id': 3333,
                  'localState': 2,
                  'fileCatalogId': 1111,
                  'computerId': 2222},
            query_args=None)])

    self.assertTrue(local_rule.key.get().is_fulfilled)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.RULE)

  def testWhitelist_NoEvent(self):

    binary = test_utils.CreateBit9Binary(file_catalog_id='1111')
    user = test_utils.CreateUser()
    local_rule = test_utils.CreateBit9Rule(
        binary.key, host_id='2222', user_key=user.key,
        policy=constants.RULE_POLICY.WHITELIST, is_fulfilled=False)

    # Mock out the Bit9 API interactions.
    file_instance = api.FileInstance(
        id=3333,
        file_catalog_id=1111,
        computer_id=2222,
        local_state=bit9_constants.APPROVAL_STATE.UNAPPROVED)
    self.PatchApiRequests([file_instance], file_instance)

    change_set.ChangeLocalState(
        binary, local_rule, bit9_constants.APPROVAL_STATE.APPROVED)

    # Verify the Bit9 API interactions.
    self.mock_ctx.ExecuteRequest.assert_has_calls([
        mock.call(
            'GET', api_route='fileInstance',
            query_args=[r'q=computerId:2222', 'q=fileCatalogId:1111']),
        mock.call(
            'POST', api_route='fileInstance',
            data={'id': 3333,
                  'localState': 2,
                  'fileCatalogId': 1111,
                  'computerId': 2222},
            query_args=None)])

    self.assertTrue(local_rule.key.get().is_fulfilled)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.RULE)

  def testWhitelist_HasEvent(self):

    binary = test_utils.CreateBit9Binary(file_catalog_id='1111')
    user = test_utils.CreateUser()
    local_rule = test_utils.CreateBit9Rule(
        binary.key, host_id='2222', user_key=user.key,
        policy=constants.RULE_POLICY.WHITELIST, is_fulfilled=False)

    # Create a Bit9Event corresponding to the Bit9Rule.
    pairs = [
        ('User', user.email),
        ('Host', '2222'),
        ('Blockable', binary.key.id()),
        ('Event', '1')]
    event_key = ndb.Key(pairs=pairs)
    first_blocked_dt = datetime.datetime.utcnow() - datetime.timedelta(hours=3)
    test_utils.CreateBit9Event(
        binary, key=event_key, first_blocked_dt=first_blocked_dt)

    # Mock out the Bit9 API interactions.
    file_instance = api.FileInstance(
        id=3333,
        file_catalog_id=1111,
        computer_id=2222,
        local_state=bit9_constants.APPROVAL_STATE.UNAPPROVED)
    self.PatchApiRequests([file_instance], file_instance)

    change_set.ChangeLocalState(
        binary, local_rule, bit9_constants.APPROVAL_STATE.APPROVED)

    # Verify the Bit9 API interactions.
    self.mock_ctx.ExecuteRequest.assert_has_calls([
        mock.call(
            'GET', api_route='fileInstance',
            query_args=[r'q=computerId:2222', 'q=fileCatalogId:1111']),
        mock.call(
            'POST', api_route='fileInstance',
            data={'id': 3333,
                  'localState': 2,
                  'fileCatalogId': 1111,
                  'computerId': 2222},
            query_args=None)])

    self.assertTrue(local_rule.key.get().is_fulfilled)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.RULE)


class ChangeLocalStatesTest(basetest.UpvoteTestCase):

  @mock.patch.object(change_set, 'ChangeLocalState')
  def testSuccess(self, mock_change_local_state):

    binary = test_utils.CreateBit9Binary(file_catalog_id='1111')
    rule_count = 11
    local_rules = test_utils.CreateBit9Rules(binary.key, rule_count)

    change_set._ChangeLocalStates(
        binary, local_rules, bit9_constants.APPROVAL_STATE.APPROVED)

    self.assertEqual(rule_count, mock_change_local_state.call_count)


class CommitBlockableChangeSetTest(bit9test.Bit9TestCase):

  def setUp(self):
    super(CommitBlockableChangeSetTest, self).setUp()

    self.binary = test_utils.CreateBit9Binary(file_catalog_id='1234')
    self.local_rule = test_utils.CreateBit9Rule(self.binary.key, host_id='5678')
    self.global_rule = test_utils.CreateBit9Rule(self.binary.key)

  def testWhitelist_LocalRule_Fulfilled(self):
    change = test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[self.local_rule.key],
        change_type=constants.RULE_POLICY.WHITELIST)

    fi = api.FileInstance(
        id=9012,
        file_catalog_id=int(self.binary.file_catalog_id),
        computer_id=int(self.local_rule.host_id),
        local_state=bit9_constants.APPROVAL_STATE.UNAPPROVED)
    self.PatchApiRequests([fi], fi)

    change_set._CommitBlockableChangeSet(self.binary.key)

    self.mock_ctx.ExecuteRequest.assert_has_calls([
        mock.call(
            'GET', api_route='fileInstance',
            query_args=[r'q=computerId:5678', 'q=fileCatalogId:1234']),
        mock.call(
            'POST', api_route='fileInstance',
            data={'id': 9012,
                  'localState': 2,
                  'fileCatalogId': 1234,
                  'computerId': 5678},
            query_args=None)])

    self.assertTrue(self.local_rule.key.get().is_fulfilled)
    self.assertTrue(self.local_rule.key.get().is_committed)
    self.assertIsNone(change.key.get())

    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.RULE)

  def testWhitelist_LocalRule_NotFulfilled(self):
    change = test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[self.local_rule.key],
        change_type=constants.RULE_POLICY.WHITELIST)
    computer = api.Computer(id=5678, sync_percent=100)
    computer.last_poll_date = datetime.datetime.utcnow()
    self.PatchApiRequests([], computer)

    change_set._CommitBlockableChangeSet(self.binary.key)

    self.mock_ctx.ExecuteRequest.assert_has_calls([
        mock.call(
            'GET', api_route='fileInstance',
            query_args=[r'q=computerId:5678', 'q=fileCatalogId:1234'])])

    self.assertIsNotNone(self.local_rule.key.get().is_fulfilled)
    self.assertFalse(self.local_rule.key.get().is_fulfilled)
    self.assertTrue(self.local_rule.key.get().is_committed)
    self.assertIsNone(change.key.get())

  def testWhitelist_LocalRule_Certificate(self):
    cert = test_utils.CreateBit9Certificate()
    local_rule = test_utils.CreateBit9Rule(cert.key, host_id='5678')
    change = test_utils.CreateRuleChangeSet(
        cert.key,
        rule_keys=[local_rule.key],
        change_type=constants.RULE_POLICY.WHITELIST)

    change_set._CommitBlockableChangeSet(cert.key)

    self.assertIsNotNone(self.local_rule.key.get().is_fulfilled)
    self.assertFalse(local_rule.key.get().is_fulfilled)
    self.assertTrue(local_rule.key.get().is_committed)
    self.assertIsNone(change.key.get())

  def testWhitelist_GlobalRule(self):
    change = test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[self.global_rule.key],
        change_type=constants.RULE_POLICY.WHITELIST)
    self.PatchApiRequests(api.Computer(id=5678))

    change_set._CommitBlockableChangeSet(self.binary.key)

    self.mock_ctx.ExecuteRequest.assert_has_calls([
        mock.call(
            'POST', api_route='fileRule',
            data={'fileCatalogId': 1234, 'fileState': 2}, query_args=None)])

    self.assertTrue(self.global_rule.key.get().is_committed)
    self.assertIsNone(change.key.get())

  def testWhitelist_GlobalRule_Certificate(self):
    cert = test_utils.CreateBit9Certificate(id='1a2b')
    global_rule = test_utils.CreateBit9Rule(cert.key, host_id='')
    change = test_utils.CreateRuleChangeSet(
        cert.key,
        rule_keys=[global_rule.key],
        change_type=constants.RULE_POLICY.WHITELIST)
    api_cert = api.Certificate(id=9012, thumbprint='1a2b', certificate_state=1)
    self.PatchApiRequests([api_cert], api_cert)

    change_set._CommitBlockableChangeSet(cert.key)

    self.mock_ctx.ExecuteRequest.assert_has_calls([
        mock.call(
            'GET', api_route='certificate',
            query_args=['q=thumbprint:1a2b']),
        mock.call(
            'POST', api_route='certificate',
            data={'id': 9012, 'thumbprint': '1a2b', 'certificateState': 2},
            query_args=None)])

    self.assertTrue(global_rule.key.get().is_committed)
    self.assertIsNone(change.key.get())

  def testWhitelist_MixedRules(self):
    other_local_rule = test_utils.CreateBit9Rule(
        self.binary.key, host_id='9012')
    change = test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[
            self.local_rule.key, other_local_rule.key, self.global_rule.key],
        change_type=constants.RULE_POLICY.WHITELIST)
    fi1 = api.FileInstance(
        id=9012,
        file_catalog_id=int(self.binary.file_catalog_id),
        computer_id=int(self.local_rule.host_id),
        local_state=bit9_constants.APPROVAL_STATE.UNAPPROVED)
    fi2 = api.FileInstance(
        id=9012,
        file_catalog_id=int(self.binary.file_catalog_id),
        computer_id=9012,
        local_state=bit9_constants.APPROVAL_STATE.UNAPPROVED)
    rule = api.FileRule(
        file_catalog_id=1234, file_state=bit9_constants.APPROVAL_STATE.APPROVED)
    self.PatchApiRequests([fi1], fi1, [fi2], fi2, rule)

    change_set._CommitBlockableChangeSet(self.binary.key)

    self.mock_ctx.ExecuteRequest.assert_has_calls([
        mock.call(
            'GET', api_route='fileInstance',
            query_args=[r'q=computerId:5678', 'q=fileCatalogId:1234']),
        mock.call(
            'POST', api_route='fileInstance',
            data={'id': 9012,
                  'localState': 2,
                  'fileCatalogId': 1234,
                  'computerId': 5678},
            query_args=None),
        mock.call(
            'GET', api_route='fileInstance',
            query_args=[r'q=computerId:9012', 'q=fileCatalogId:1234']),
        mock.call(
            'POST', api_route='fileInstance',
            data={'id': 9012,
                  'localState': 2,
                  'fileCatalogId': 1234,
                  'computerId': 9012},
            query_args=None),
        mock.call(
            'POST', api_route='fileRule',
            data={'fileCatalogId': 1234, 'fileState': 2}, query_args=None),
    ])

    self.assertTrue(self.local_rule.key.get().is_fulfilled)
    self.assertTrue(self.local_rule.key.get().is_committed)
    self.assertTrue(other_local_rule.key.get().is_fulfilled)
    self.assertTrue(other_local_rule.key.get().is_committed)
    self.assertTrue(self.global_rule.key.get().is_committed)
    self.assertIsNone(change.key.get())

    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.RULE] * 2)

  def testBlacklist_GlobalRule(self):
    change = test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[self.global_rule.key],
        change_type=constants.RULE_POLICY.BLACKLIST)
    rule = api.FileRule(
        file_catalog_id=1234,
        file_state=bit9_constants.APPROVAL_STATE.UNAPPROVED)
    self.PatchApiRequests(rule)

    change_set._CommitBlockableChangeSet(self.binary.key)

    self.mock_ctx.ExecuteRequest.assert_has_calls([
        mock.call(
            'POST', api_route='fileRule',
            data={'fileCatalogId': 1234, 'fileState': 3}, query_args=None)])

    self.assertTrue(self.global_rule.key.get().is_committed)
    self.assertIsNone(change.key.get())

  def testBlacklist_GlobalRule_Multiple(self):
    other_global_rule = test_utils.CreateBit9Rule(self.binary.key)
    test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[self.global_rule.key, other_global_rule.key],
        change_type=constants.RULE_POLICY.BLACKLIST)

    with self.assertRaises(deferred.PermanentTaskFailure):
      change_set._CommitBlockableChangeSet(self.binary.key)

  def testBlacklist_MixedRules(self):
    test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[self.local_rule.key, self.global_rule.key],
        change_type=constants.RULE_POLICY.BLACKLIST)

    with self.assertRaises(deferred.PermanentTaskFailure):
      change_set._CommitBlockableChangeSet(self.binary.key)

  def testRemove_MixedRules(self):
    other_local_rule = test_utils.CreateBit9Rule(
        self.binary.key, host_id='9012')
    change = test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[
            self.local_rule.key, other_local_rule.key, self.global_rule.key],
        change_type=constants.RULE_POLICY.REMOVE)
    fi1 = api.FileInstance(
        id=9012,
        file_catalog_id=int(self.binary.file_catalog_id),
        computer_id=int(self.local_rule.host_id),
        local_state=bit9_constants.APPROVAL_STATE.APPROVED)
    fi2 = api.FileInstance(
        id=9012,
        file_catalog_id=int(self.binary.file_catalog_id),
        computer_id=int(other_local_rule.host_id),
        local_state=bit9_constants.APPROVAL_STATE.APPROVED)
    rule = api.FileRule(
        file_catalog_id=1234, file_state=bit9_constants.APPROVAL_STATE.APPROVED)
    self.PatchApiRequests([fi1], fi1, [fi2], fi2, rule)

    change_set._CommitBlockableChangeSet(self.binary.key)

    self.mock_ctx.ExecuteRequest.assert_has_calls([
        mock.call(
            'GET', api_route='fileInstance',
            query_args=[r'q=computerId:5678', 'q=fileCatalogId:1234']),
        mock.call(
            'POST', api_route='fileInstance',
            data={'id': 9012,
                  'localState': 1,
                  'fileCatalogId': 1234,
                  'computerId': 5678},
            query_args=None),
        mock.call(
            'GET', api_route='fileInstance',
            query_args=[r'q=computerId:9012', 'q=fileCatalogId:1234']),
        mock.call(
            'POST', api_route='fileInstance',
            data={'id': 9012,
                  'localState': 1,
                  'fileCatalogId': 1234,
                  'computerId': 9012},
            query_args=None),
        mock.call(
            'POST', api_route='fileRule',
            data={'fileCatalogId': 1234, 'fileState': 1}, query_args=None),
    ])

    self.assertTrue(self.local_rule.key.get().is_fulfilled)
    self.assertTrue(self.local_rule.key.get().is_committed)
    self.assertTrue(other_local_rule.key.get().is_fulfilled)
    self.assertTrue(other_local_rule.key.get().is_committed)
    self.assertTrue(self.global_rule.key.get().is_committed)
    self.assertIsNone(change.key.get())

    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.RULE] * 2)

  def testTailDefer(self):
    test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[self.local_rule.key],
        change_type=constants.RULE_POLICY.WHITELIST)
    test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[self.global_rule.key],
        change_type=constants.RULE_POLICY.WHITELIST)
    with mock.patch.object(change_set, '_Whitelist'):
      change_set._CommitBlockableChangeSet(self.binary.key)
      # Tail defer should have been added.
      self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 1)

      # Only the local rule should have been committed first.
      self.assertTrue(self.local_rule.key.get().is_committed)
      self.assertFalse(self.global_rule.key.get().is_committed)
      self.assertEntityCount(rule_models.RuleChangeSet, 1)

      # Run the deferred commit attempt.
      self.RunDeferredTasks(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE)
      # Tail defer should not have been added as there are no more changes.
      self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 0)

      # Both rules should now have been committed.
      self.assertTrue(self.local_rule.key.get().is_committed)
      self.assertTrue(self.global_rule.key.get().is_committed)
      self.assertEntityCount(rule_models.RuleChangeSet, 0)

  def testNoChange(self):
    with mock.patch.object(change_set, '_CommitChangeSet') as mock_commit:
      change_set._CommitBlockableChangeSet(self.binary.key)

      self.assertFalse(mock_commit.called)


class DeferCommitBlockableChangeSetTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(DeferCommitBlockableChangeSetTest, self).setUp()

    self.binary = test_utils.CreateBit9Binary(file_catalog_id='1234')
    self.local_rule = test_utils.CreateBit9Rule(self.binary.key, host_id='5678')
    self.change = test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[self.local_rule.key],
        change_type=constants.RULE_POLICY.WHITELIST)

  def testTailDefer_MoreChanges(self):
    test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[self.local_rule.key],
        change_type=constants.RULE_POLICY.BLACKLIST)
    with mock.patch.object(change_set, '_CommitChangeSet') as mock_commit:
      change_set.DeferCommitBlockableChangeSet(self.binary.key)

      self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 1)
      self.RunDeferredTasks(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE)
      # Tail defer task for remaining change.
      self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 1)

      mock_commit.assert_called_once_with(self.change.key)

  def testTailDefer_NoMoreChanges(self):
    with mock.patch.object(change_set, '_CommitChangeSet') as mock_commit:
      change_set.DeferCommitBlockableChangeSet(self.binary.key)

      self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 1)
      self.RunDeferredTasks(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE)
      self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 0)

      mock_commit.assert_called_once_with(self.change.key)

  def testNoTailDefer(self):
    with mock.patch.object(change_set, '_CommitChangeSet') as mock_commit:
      change_set.DeferCommitBlockableChangeSet(
          self.binary.key, tail_defer=False)

      self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 1)
      self.RunDeferredTasks(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE)
      self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 0)

      mock_commit.assert_called_once_with(self.change.key)


if __name__ == '__main__':
  absltest.main()
