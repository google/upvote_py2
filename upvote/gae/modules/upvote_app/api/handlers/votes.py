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

"""Views related to votes."""
import datetime
import httplib
import logging

from google.appengine.ext import ndb

from upvote.gae.modules.upvote_app.api import monitoring
from upvote.gae.modules.upvote_app.api.handlers import base
from upvote.gae.modules.upvote_app.lib import voting
from upvote.gae.shared.common import handlers
from upvote.gae.shared.common import settings
from upvote.gae.shared.common import xsrf_utils
from upvote.gae.shared.models import base as base_db
from upvote.gae.shared.models import utils
from upvote.shared import constants


def _PopulateCandidateId(votes):
  vote_dicts = []
  for vote in votes:
    vote_dict = vote.to_dict()
    vote_dict['candidate_id'] = vote.key.parent().parent().id()
    vote_dicts.append(vote_dict)
  return vote_dicts


class VoteQueryHandler(base.BaseQueryHandler):
  """Handler for querying votes."""

  MODEL_CLASS = base_db.Vote

  @property
  def RequestCounter(self):
    return monitoring.vote_requests

  @base.RequireCapability(constants.PERMISSIONS.VIEW_VOTES)
  @handlers.RecordRequest
  def get(self):
    self._Query(callback=_PopulateCandidateId)

  def _QueryModel(self, search_dict):
    candidate_id = search_dict.pop('candidateId', None)
    ancestor_key = (
        ndb.Key(base_db.Blockable, candidate_id) if candidate_id else None)

    query = super(VoteQueryHandler, self)._QueryModel(
        search_dict, ancestor=ancestor_key)

    return query.filter(base_db.Vote.in_effect == True)  # pylint: disable=g-explicit-bool-comparison


class VoteHandler(base.BaseHandler):
  """Handler for viewing individual votes."""

  @base.RequireCapability(constants.PERMISSIONS.VIEW_VOTES)
  def get(self, vote_key):
    logging.debug('Vote handler get method called with key: %s', vote_key)
    key = utils.GetKeyFromUrlsafe(vote_key)
    if not key:
      self.abort(
          httplib.BAD_REQUEST,
          explanation='Vote key %s could not be parsed' % vote_key)

    vote = key.get()
    if vote:
      response = vote.to_dict()
      response['candidate_id'] = vote.key.parent().parent().id()
      self.respond_json(response)
    else:
      self.abort(httplib.NOT_FOUND, explanation='Vote not found.')


class VoteCastHandler(base.BaseHandler):
  """Handler for casting votes."""

  def _GetVoteWeight(self, role):
    if not role:
      return None

    role_weights = settings.VOTING_WEIGHTS
    vote_weight = role_weights.get(role)
    if vote_weight is None:
      self.abort(
          httplib.BAD_REQUEST,
          explanation='Invalid role provided: %s' % role)

    valid_access = role in self.user.roles or self.user.is_admin
    if not valid_access:
      self.abort(
          httplib.FORBIDDEN,
          explanation='User "%s" does not have role: %s' % (
              self.user.nickname, role))

    return vote_weight

  @xsrf_utils.RequireToken
  def post(self, blockable_id):
    """Handle votes from users."""
    logging.debug('Vote handler post method called.')

    # Update the user's last vote date
    self.user.last_vote_dt = datetime.datetime.utcnow()
    self.user.put()

    was_yes_vote = (self.request.get('wasYesVote') == 'true')
    role = self.request.get('asRole')
    vote_weight = self._GetVoteWeight(role)

    try:
      ballot_box = voting.GetBallotBox(blockable_id)
      ballot_box.ResolveVote(was_yes_vote, self.user, vote_weight)
    except voting.DuplicateVoteError:
      self.abort(httplib.CONFLICT, explanation='Vote already exists')
    except voting.OperationNotAllowed as e:
      self.abort(httplib.FORBIDDEN, explanation=e.message)
    except voting.BlockableNotFound:
      self.abort(httplib.NOT_FOUND, explanation='Blockable not found')
    except voting.UnsupportedBlockableType as e:
      self.abort(httplib.BAD_REQUEST, explanation=e.message)
    else:
      self.respond_json({
          'blockable': ballot_box.blockable, 'vote': ballot_box.new_vote})

  def get(self, blockable_id):
    """Gets user's vote for the given blockable."""
    logging.debug('Vote handler get method called for %s.', blockable_id)

    ancestor_key = utils.ConcatenateKeys(
        ndb.Key(base_db.Blockable, blockable_id), self.user.key)
    # pylint: disable=g-explicit-bool-comparison
    vote = base_db.Vote.query(
        base_db.Vote.in_effect == True, ancestor=ancestor_key).get()
    # pylint: enable=g-explicit-bool-comparison
    self.respond_json(vote)
