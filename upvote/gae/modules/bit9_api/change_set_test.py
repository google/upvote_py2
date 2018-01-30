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

from absl.testing import absltest

from upvote.gae.modules.bit9_api import change_set
from upvote.gae.modules.bit9_api import constants as bit9_constants
from upvote.gae.modules.bit9_api import utils
from upvote.gae.modules.bit9_api.api import api
from upvote.gae.shared.common import basetest
from upvote.gae.shared.models import bit9
from upvote.gae.shared.models import test_utils
from upvote.shared import constants


class CommitBlockableChangeSetTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(CommitBlockableChangeSetTest, self).setUp()

    self.Patch(utils, 'CONTEXT')

    self.binary = test_utils.CreateBit9Binary(file_catalog_id='1234')
    self.local_rule = test_utils.CreateBit9Rule(self.binary.key, host_id='5678')
    self.global_rule = test_utils.CreateBit9Rule(self.binary.key)

  def _PatchApiRequests(self, *results):
    requests = []
    for batch in results:
      if isinstance(batch, list):
        requests.append([obj.to_raw_dict() for obj in batch])
      else:
        requests.append(batch.to_raw_dict())
    utils.CONTEXT.ExecuteRequest.side_effect = requests

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
    self._PatchApiRequests([fi], fi)

    change_set.CommitBlockableChangeSet(self.binary.key)

    utils.CONTEXT.ExecuteRequest.assert_has_calls([
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

  def testWhitelist_LocalRule_NotFulfilled(self):
    change = test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[self.local_rule.key],
        change_type=constants.RULE_POLICY.WHITELIST)
    computer = api.Computer(id=5678, sync_percent=100)
    computer.last_poll_date = datetime.datetime.utcnow()
    self._PatchApiRequests([], computer)

    change_set.CommitBlockableChangeSet(self.binary.key)

    utils.CONTEXT.ExecuteRequest.assert_has_calls([
        mock.call(
            'GET', api_route='fileInstance',
            query_args=[r'q=computerId:5678', 'q=fileCatalogId:1234'])])

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

    change_set.CommitBlockableChangeSet(cert.key)

    self.assertFalse(local_rule.key.get().is_fulfilled)
    self.assertTrue(local_rule.key.get().is_committed)
    self.assertIsNone(change.key.get())

  def testWhitelist_GlobalRule(self):
    change = test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[self.global_rule.key],
        change_type=constants.RULE_POLICY.WHITELIST)
    self._PatchApiRequests(api.Computer(id=5678))

    change_set.CommitBlockableChangeSet(self.binary.key)

    utils.CONTEXT.ExecuteRequest.assert_has_calls([
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
    self._PatchApiRequests([api_cert], api_cert)

    change_set.CommitBlockableChangeSet(cert.key)

    utils.CONTEXT.ExecuteRequest.assert_has_calls([
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
    self._PatchApiRequests([fi1], fi1, [fi2], fi2, rule)

    change_set.CommitBlockableChangeSet(self.binary.key)

    utils.CONTEXT.ExecuteRequest.assert_has_calls([
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

  def testBlacklist_GlobalRule(self):
    change = test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[self.global_rule.key],
        change_type=constants.RULE_POLICY.BLACKLIST)
    rule = api.FileRule(
        file_catalog_id=1234,
        file_state=bit9_constants.APPROVAL_STATE.UNAPPROVED)
    self._PatchApiRequests(rule)

    change_set.CommitBlockableChangeSet(self.binary.key)

    utils.CONTEXT.ExecuteRequest.assert_has_calls([
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
      change_set.CommitBlockableChangeSet(self.binary.key)

  def testBlacklist_MixedRules(self):
    test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[self.local_rule.key, self.global_rule.key],
        change_type=constants.RULE_POLICY.BLACKLIST)

    with self.assertRaises(deferred.PermanentTaskFailure):
      change_set.CommitBlockableChangeSet(self.binary.key)

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
    self._PatchApiRequests([fi1], fi1, [fi2], fi2, rule)

    change_set.CommitBlockableChangeSet(self.binary.key)

    utils.CONTEXT.ExecuteRequest.assert_has_calls([
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
      change_set.CommitBlockableChangeSet(self.binary.key)
      # Tail defer should have been added.
      self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 1)

      # Only the local rule should have been committed first.
      self.assertTrue(self.local_rule.key.get().is_committed)
      self.assertFalse(self.global_rule.key.get().is_committed)
      self.assertEntityCount(bit9.RuleChangeSet, 1)

      # Run the deferred commit attempt.
      self.RunDeferredTasks(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE)
      # Tail defer should not have been added as there are no more changes.
      self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 0)

      # Both rules should now have been committed.
      self.assertTrue(self.local_rule.key.get().is_committed)
      self.assertTrue(self.global_rule.key.get().is_committed)
      self.assertEntityCount(bit9.RuleChangeSet, 0)

  def testNoChange(self):
    with mock.patch.object(change_set, 'CommitChangeSet') as mock_commit:
      change_set.CommitBlockableChangeSet(self.binary.key)

      self.assertFalse(mock_commit.called)

  def testFailure_ExceedRetryLimit(self):
    test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[self.local_rule.key],
        change_type=constants.RULE_POLICY.WHITELIST)

    computer = api.Computer(id=5678, sync_percent=90)
    computer.last_poll_date = datetime.datetime.utcnow()
    self._PatchApiRequests(
        [], computer, [], computer, [], computer, [], computer)

    with self.assertRaises(deferred.PermanentTaskFailure):
      change_set.CommitBlockableChangeSet(self.binary.key)

  def testFailure_RetryAndSucceed(self):
    test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[self.local_rule.key],
        change_type=constants.RULE_POLICY.WHITELIST)

    fi = api.FileInstance(
        id=9012,
        file_catalog_id=int(self.binary.file_catalog_id),
        computer_id=int(self.local_rule.host_id),
        local_state=bit9_constants.APPROVAL_STATE.UNAPPROVED)
    computer = api.Computer(id=5678, sync_percent=90)
    computer.last_poll_date = datetime.datetime.utcnow()
    self._PatchApiRequests([], computer, [], computer, [], computer, [fi], fi)

    change_set.CommitBlockableChangeSet(self.binary.key)

    expected_call = mock.call(
        'POST', api_route='fileInstance',
        data={'id': 9012,
              'localState': 2,
              'fileCatalogId': 1234,
              'computerId': 5678},
        query_args=None)
    self.assertTrue(expected_call in utils.CONTEXT.ExecuteRequest.mock_calls)


class DeferCommitTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(DeferCommitTest, self).setUp()

    self.binary = test_utils.CreateBit9Binary(file_catalog_id='1234')
    self.local_rule = test_utils.CreateBit9Rule(self.binary.key, host_id='5678')
    self.change = test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[self.local_rule.key],
        change_type=constants.RULE_POLICY.WHITELIST)

  def testDeferCommitBlockableChangeSet_TailDefer_MoreChanges(self):
    test_utils.CreateRuleChangeSet(
        self.binary.key,
        rule_keys=[self.local_rule.key],
        change_type=constants.RULE_POLICY.BLACKLIST)
    with mock.patch.object(change_set, 'CommitChangeSet') as mock_commit:
      change_set.DeferCommitBlockableChangeSet(self.binary.key)

      self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 1)
      self.RunDeferredTasks(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE)
      # Tail defer task for remaining change.
      self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 1)

      mock_commit.assert_called_once_with(self.change.key)

  def testDeferCommitBlockableChangeSet_TailDefer_NoMoreChanges(self):
    with mock.patch.object(change_set, 'CommitChangeSet') as mock_commit:
      change_set.DeferCommitBlockableChangeSet(self.binary.key)

      self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 1)
      self.RunDeferredTasks(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE)
      self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 0)

      mock_commit.assert_called_once_with(self.change.key)

  def testDeferCommitBlockableChangeSet_NoTailDefer(self):
    with mock.patch.object(change_set, 'CommitChangeSet') as mock_commit:
      change_set.DeferCommitBlockableChangeSet(
          self.binary.key, tail_defer=False)

      self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 1)
      self.RunDeferredTasks(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE)
      self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 0)

      mock_commit.assert_called_once_with(self.change.key)

  def testDeferCommitChangeSet(self):
    with mock.patch.object(change_set, '_Whitelist') as mock_whitelist:
      change_set.DeferCommitChangeSet(self.change.key)

      self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 1)
      self.RunDeferredTasks(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE)
      self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 0)

      self.assertTrue(mock_whitelist.called)


if __name__ == '__main__':
  absltest.main()
