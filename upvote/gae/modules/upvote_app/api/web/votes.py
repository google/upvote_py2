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

import webapp2
from webapp2_extras import routes

from google.appengine.ext import ndb

from upvote.gae import settings
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import base as base_models
from upvote.gae.datastore.models import vote as vote_models
from upvote.gae.lib.voting import api as voting_api
from upvote.gae.modules.upvote_app.api.web import monitoring
from upvote.gae.utils import handler_utils
from upvote.gae.utils import xsrf_utils
from upvote.shared import constants


def _PopulateCandidateId(votes):
  vote_dicts = []
  for vote in votes:
    vote_dict = vote.to_dict()
    vote_dict['candidate_id'] = vote.key.parent().parent().id()
    vote_dicts.append(vote_dict)
  return vote_dicts


class VoteQueryHandler(handler_utils.UserFacingQueryHandler):
  """Handler for querying votes."""

  MODEL_CLASS = vote_models.Vote

  @property
  def RequestCounter(self):
    return monitoring.vote_requests

  @handler_utils.RequireCapability(constants.PERMISSIONS.VIEW_VOTES)
  @handler_utils.RecordRequest
  def get(self):
    self._Query(callback=_PopulateCandidateId)

  def _QueryModel(self, search_dict):
    candidate_id = search_dict.pop('candidateId', None)
    ancestor_key = (
        ndb.Key(base_models.Blockable, candidate_id) if candidate_id else None)

    query = super(VoteQueryHandler, self)._QueryModel(
        search_dict, ancestor=ancestor_key)

    return query.filter(vote_models.Vote.in_effect == True)  # pylint: disable=g-explicit-bool-comparison, singleton-comparison


class VoteHandler(handler_utils.UserFacingHandler):
  """Handler for viewing individual votes."""

  @handler_utils.RequireCapability(constants.PERMISSIONS.VIEW_VOTES)
  def get(self, vote_key):
    logging.info('Vote handler get method called with key: %s', vote_key)
    key = datastore_utils.GetKeyFromUrlsafe(vote_key)
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


class VoteCastHandler(handler_utils.UserFacingHandler):
  """Handler for casting votes."""

  def _GetVoteWeight(self, role):
    if not role:
      return self.user.vote_weight

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

    was_yes_vote = (self.request.get('wasYesVote') == 'true')
    role = self.request.get('asRole', default_value=self.user.highest_role)
    vote_weight = self._GetVoteWeight(role)

    logging.info(
        'User %s is using the %s role to cast a %s%s vote for %s',
        self.user.nickname, role, '+' if was_yes_vote else '-', vote_weight,
        blockable_id)

    try:
      vote = voting_api.Vote(self.user, blockable_id, was_yes_vote, vote_weight)
    except voting_api.BlockableNotFoundError:
      self.abort(httplib.NOT_FOUND, explanation='Application not found')
    except voting_api.UnsupportedClientError:
      self.abort(httplib.BAD_REQUEST, explanation='Unsupported client')
    except voting_api.InvalidVoteWeightError:
      self.abort(httplib.BAD_REQUEST, explanation='Invalid voting weight')
    except voting_api.DuplicateVoteError:
      self.abort(httplib.CONFLICT, explanation='Vote already exists')
    except voting_api.OperationNotAllowedError as e:
      self.abort(httplib.FORBIDDEN, explanation=e.message)
    except Exception as e:  # pylint: disable=broad-except
      self.abort(httplib.INTERNAL_SERVER_ERROR, explanation=e.message)
    else:

      # Update the user's last vote date
      self.user.last_vote_dt = datetime.datetime.utcnow()
      self.user.put()

      self.respond_json({
          'blockable': base_models.Blockable.get_by_id(blockable_id),
          'vote': vote})

  def get(self, blockable_id):
    """Gets user's vote for the given blockable."""
    logging.info('Vote handler get method called for %s.', blockable_id)

    ancestor_key = datastore_utils.ConcatenateKeys(
        ndb.Key(base_models.Blockable, blockable_id), self.user.key)
    # pylint: disable=g-explicit-bool-comparison, singleton-comparison
    vote = vote_models.Vote.query(
        vote_models.Vote.in_effect == True, ancestor=ancestor_key).get()
    # pylint: enable=g-explicit-bool-comparison, singleton-comparison
    self.respond_json(vote)


# The Webapp2 routes defined for these handlers.
ROUTES = routes.PathPrefixRoute('/votes', [
    webapp2.Route(
        '/cast/<blockable_id>',
        handler=VoteCastHandler),
    webapp2.Route(
        '/query',
        handler=VoteQueryHandler),
    webapp2.Route(
        '/<vote_key>',
        handler=VoteHandler),
])
