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

"""Model definitions for Upvote votes."""

from google.appengine.ext import ndb

from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import mixin
from upvote.gae.datastore.models import user as user_models
from upvote.shared import constants


_IN_EFFECT_KEY_NAME = 'InEffect'


class Vote(mixin.Base, ndb.Model):
  """An individual vote on a blockable cast by a user.

  key = Key(Blockable, hash) -> Key(User, email) -> Key(Vote, 'InEffect')

  Attributes:
    user_email: str, the email of the voting user at the time of the vote.
    was_yes_vote: boolean, True if the vote was "Yes."
    recorded_dt: DateTime, time of vote.
    value: Int, the value of the vote at the time of voting, based on the value
        of the users vote.
    candidate_type: str, the type of blockable being voted on.
    blockable_key: Key, the key of the blockable being voted on.
    in_effect: boolean, True if the vote counts towards the blockable score.
  """

  def _ComputeBlockableKey(self):
    if not self.key:
      return None
    pairs = self.key.pairs()
    if len(pairs) < 3:
      return None
    return ndb.Key(pairs=pairs[:-2])

  user_email = ndb.StringProperty(required=True)
  was_yes_vote = ndb.BooleanProperty(required=True, default=True)
  recorded_dt = ndb.DateTimeProperty(auto_now_add=True)
  weight = ndb.IntegerProperty(default=0)
  candidate_type = ndb.StringProperty(
      choices=constants.RULE_TYPE.SET_ALL, required=True)
  blockable_key = ndb.ComputedProperty(_ComputeBlockableKey)
  in_effect = ndb.ComputedProperty(
      lambda self: self.key and self.key.flat()[-1] == _IN_EFFECT_KEY_NAME)

  @classmethod
  def GetKey(cls, blockable_key, user_key, in_effect=True):
    # In the in_effect == False case, the None ID field of the key will cause
    # NDB to generate a random one when the vote is put.
    vote_id = _IN_EFFECT_KEY_NAME if in_effect else None
    return datastore_utils.ConcatenateKeys(
        blockable_key, user_key, ndb.Key(Vote, vote_id))

  @property
  def effective_weight(self):
    return self.weight if self.was_yes_vote else -self.weight

  @property
  def user_key(self):
    return ndb.Key(user_models.User, self.user_email.lower())
