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

"""Handlers related to rules."""
import httplib
import logging

import webapp2
from webapp2_extras import routes

from google.appengine.ext import ndb

from upvote.gae.datastore import utils
from upvote.gae.datastore.models import base as base_models
from upvote.gae.datastore.models import santa as santa_models
from upvote.gae.modules.upvote_app.api import monitoring
from upvote.gae.modules.upvote_app.api.web import base
from upvote.gae.shared.common import handlers
from upvote.shared import constants


class RuleQueryHandler(base.BaseQueryHandler):
  """Handler for querying rules."""

  MODEL_CLASS = base_models.Rule

  @property
  def RequestCounter(self):
    return monitoring.rule_requests

  @base.RequireCapability(constants.PERMISSIONS.VIEW_RULES)
  @handlers.RecordRequest
  def get(self):
    self._Query()

  def _QueryModel(self, search_dict):
    target_id = search_dict.pop('targetId', None)

    ancestor_key = (
        ndb.Key(base_models.Blockable, target_id) if target_id else None)
    return super(RuleQueryHandler, self)._QueryModel(
        search_dict, ancestor=ancestor_key)


class SantaRuleQueryHandler(RuleQueryHandler):
  """Handler for querying santa rules."""

  MODEL_CLASS = santa_models.SantaRule


class RuleHandler(base.BaseHandler):
  """Handler for interacting with individual rules."""

  @base.RequireCapability(constants.PERMISSIONS.VIEW_RULES)
  def get(self, rule_key):
    logging.debug('Rule handler get method called with key: %s', rule_key)
    key = utils.GetKeyFromUrlsafe(rule_key)
    if not key:
      self.abort(
          httplib.BAD_REQUEST,
          explanation='Rule key %s could not be parsed' % rule_key)

    rule = key.get()
    if rule:
      response = rule.to_dict()
      response['target_id'] = rule.key.parent().id()
      self.respond_json(response)
    else:
      self.abort(httplib.NOT_FOUND, explanation='Rule not found')


# The Webapp2 routes defined for these handlers.
ROUTES = routes.PathPrefixRoute('/rules', [
    webapp2.Route(
        '/query/santa',
        handler=SantaRuleQueryHandler),
    webapp2.Route(
        '/query',
        handler=RuleQueryHandler),
    webapp2.Route(
        '/<rule_key>',
        handler=RuleHandler),
])
