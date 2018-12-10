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

"""Unit tests for vote.py."""

from google.appengine.ext import ndb

from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import vote as vote_models
from upvote.gae.lib.testing import basetest


class VoteTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(VoteTest, self).setUp()
    self.blockable = test_utils.CreateBlockable()
    self.user = test_utils.CreateUser()

  def testSetKey(self):
    expected_key = ndb.Key(flat=(
        self.blockable.key.flat() + self.user.key.flat() +
        ('Vote', vote_models._IN_EFFECT_KEY_NAME)))
    key = vote_models.Vote.GetKey(self.blockable.key, self.user.key)
    self.assertEqual(expected_key, key)

  def testSetKey_NotInEffect(self):
    expected_key = ndb.Key(flat=(
        self.blockable.key.flat() + self.user.key.flat() +
        ('Vote', None)))
    key = vote_models.Vote.GetKey(
        self.blockable.key, self.user.key, in_effect=False)
    self.assertEqual(expected_key, key)

    # Putting the vote results in a random ID being generated.
    vote = test_utils.CreateVote(self.blockable)
    vote.key = key
    vote.put()
    self.assertIsNotNone(vote.key.id())

  def testBlockableKey(self):
    vote = test_utils.CreateVote(self.blockable, user_email=self.user.email)
    vote.key = vote_models.Vote.GetKey(self.blockable.key, self.user.key)
    self.assertEqual(self.blockable.key, vote.blockable_key)

  def testBlockableKey_MultiPartKey(self):
    vote = test_utils.CreateVote(self.blockable, user_email=self.user.email)
    # Add another test_blockable key to simulate a length-two blockable key.
    vote.key = datastore_utils.ConcatenateKeys(
        self.blockable.key,
        vote_models.Vote.GetKey(self.blockable.key, self.user.key))

    self.assertIsNotNone(vote.blockable_key)
    self.assertLen(vote.blockable_key.pairs(), 2)
    self.assertEqual(self.blockable.key, vote.blockable_key.parent())

  def testBlockableKey_NoKey(self):
    vote = test_utils.CreateVote(self.blockable, user_email=self.user.email)
    vote.key = None
    self.assertIsNone(vote.blockable_key)

  def testBlockableKey_BadKey(self):
    vote = test_utils.CreateVote(self.blockable, user_email=self.user.email)
    # Take out User key section.
    vote.key = datastore_utils.ConcatenateKeys(
        self.blockable.key, ndb.Key(vote_models.Vote, vote.key.id()))
    self.assertIsNone(vote.blockable_key)

  def testUserKey(self):
    vote = test_utils.CreateVote(self.blockable, user_email=self.user.email)
    self.assertEqual(self.user.key, vote.user_key)

  def testInEffect(self):
    vote = test_utils.CreateVote(self.blockable)
    self.assertTrue(vote.in_effect)
    vote.key = None
    self.assertFalse(vote.in_effect)


if __name__ == '__main__':
  basetest.main()
