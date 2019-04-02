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

"""Unit tests for base.py."""


import mock

from google.appengine.ext import ndb

from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import base
from upvote.gae.datastore.models import cert as cert_models
from upvote.gae.datastore.models import vote as vote_models
from upvote.gae.lib.testing import basetest
from upvote.gae.utils import user_utils


_TEST_EMAIL = user_utils.UsernameToEmail('testemail')


class BlockableTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(BlockableTest, self).setUp()

    self.blockable_1 = test_utils.CreateBlockable()
    self.blockable_2 = test_utils.CreateBlockable()

    self.user = test_utils.CreateUser(email=_TEST_EMAIL)
    self.Login(self.user.email)

  def testAvoidInitialScoreCalculation(self):
    b = base.Blockable(id_type='SHA256')
    with mock.patch.object(b, 'GetVotes', return_value=[]) as get_votes_mock:
      # First put should just set the score to be 0 and avoid the Vote query.
      b.put()
      self.assertFalse(get_votes_mock.called)

      # Now that b has a score value, it should do the Vote query to update it.
      b.put()
      self.assertTrue(get_votes_mock.called)

  def testGetVotes(self):
    self.assertLen(self.blockable_1.GetVotes(), 0)
    self.assertLen(self.blockable_2.GetVotes(), 0)

    test_utils.CreateVotes(self.blockable_1, 3)
    test_utils.CreateVotes(self.blockable_2, 2)

    self.assertLen(self.blockable_1.GetVotes(), 3)
    self.assertLen(self.blockable_2.GetVotes(), 2)

  def testGetVotes_Inactive(self):
    self.assertLen(self.blockable_1.GetVotes(), 0)

    test_utils.CreateVotes(self.blockable_1, 2)

    self.assertLen(self.blockable_1.GetVotes(), 2)

    votes = vote_models.Vote.query().fetch()
    new_votes = []
    for vote in votes:
      new_key = ndb.Key(flat=vote.key.flat()[:-1] + (None,))
      new_votes.append(datastore_utils.CopyEntity(vote, new_key=new_key))
    ndb.delete_multi(vote.key for vote in votes)
    ndb.put_multi(new_votes)

    self.assertLen(self.blockable_1.GetVotes(), 0)

  def testGetEvents(self):
    self.assertLen(self.blockable_1.GetEvents(), 0)
    test_utils.CreateEvents(self.blockable_1, 5)
    self.assertLen(self.blockable_1.GetEvents(), 5)

  def testToDict_Score(self):
    blockable = test_utils.CreateBlockable()
    test_utils.CreateVote(blockable)
    # Recalculate the 'score' property
    blockable.put()

    # Mock out the blockable's _CalculateScore function.
    with mock.patch.object(
        blockable._properties['score'], '_func') as calc_mock:  # pylint: disable=protected-access
      blockable_dict = blockable.to_dict()
      self.assertFalse(calc_mock.called)
      self.assertIn('score', blockable_dict)
      self.assertEqual(1, blockable_dict['score'])

  def testGetById(self):
    blockable = test_utils.CreateBlockable()
    sha256 = blockable.key.id()
    self.assertIsNotNone(base.Blockable.get_by_id(sha256.lower()))
    self.assertIsNotNone(base.Blockable.get_by_id(sha256.upper()))

  def testIsInstance(self):
    blockable = test_utils.CreateBlockable()
    self.assertTrue(blockable.IsInstance('Blockable'))
    self.assertTrue(blockable.IsInstance('blockable'))
    self.assertTrue(blockable.IsInstance('BLOCKABLE'))
    self.assertFalse(blockable.IsInstance('SomethingElse'))


class BinaryTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(BinaryTest, self).setUp()

    self.blockable = test_utils.CreateBlockableEntity(base.Binary)

    self.user = test_utils.CreateUser(email=_TEST_EMAIL)
    self.Login(self.user.email)

  def testCertId(self):
    cert = test_utils.CreateBlockableEntity(cert_models.Certificate)
    self.blockable.cert_key = cert.key
    self.blockable.put()

    self.assertEqual(cert.key.id(), self.blockable.cert_id)

  def testCertId_Empty(self):
    # Blockable with no cert_key should have no cert_id.
    self.assertIsNone(self.blockable.cert_id)

  def testTranslatePropertyQuery_CertId(self):
    field, val = 'cert_id', 'bar'

    new_field, new_val = base.Binary.TranslatePropertyQuery(field, val)

    self.assertEqual(val, ndb.Key(urlsafe=new_val).id())
    self.assertEqual('cert_key', new_field)

  def testTranslatePropertyQuery_CertId_NoQueryValue(self):
    field, val = 'cert_id', None

    new_field, new_val = base.Binary.TranslatePropertyQuery(field, val)

    self.assertIsNone(new_val)
    self.assertEqual('cert_key', new_field)

  def testTranslatePropertyQuery_NotCertId(self):
    pair = ('foo', 'bar')
    self.assertEqual(pair, base.Binary.TranslatePropertyQuery(*pair))

  def testToDict(self):
    self.assertIn('cert_id', self.blockable.to_dict())

  def testIsInstance(self):
    binary = test_utils.CreateBlockableEntity(base.Binary)
    self.assertTrue(binary.IsInstance('Blockable'))
    self.assertTrue(binary.IsInstance('Binary'))
    self.assertFalse(binary.IsInstance('SomethingElse'))


if __name__ == '__main__':
  basetest.main()
