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

"""Unit tests for Rule handlers."""

import six.moves.http_client

import webapp2

from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import rule as rule_models
from upvote.gae.lib.testing import basetest
from upvote.gae.modules.upvote_app.api.web import rules


class RulesTest(basetest.UpvoteTestCase):
  """Base class for Rule handler tests."""

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[rules.ROUTES])
    super(RulesTest, self).setUp(wsgi_app=app)

    self.blockable1 = test_utils.CreateBlockable()
    self.blockable2 = test_utils.CreateBlockable()

    self.rule_1 = rule_models.Rule(
        parent=self.blockable1.key,
        id=123456,
        rule_type='BINARY',
        policy='WHITELIST')
    self.rule_2 = rule_models.Rule(
        parent=self.blockable2.key,
        id=123457,
        rule_type='BINARY',
        policy='BLACKLIST')
    self.rule_3 = rule_models.SantaRule(
        parent=self.blockable2.key,
        id=123458,
        rule_type='BINARY',
        policy='WHITELIST')
    self.rule_1.put()
    self.rule_2.put()
    self.rule_3.put()

    self.PatchValidateXSRFToken()


class RuleQueryHandler(RulesTest):

  QUERY_ROUTE = '/rules/query'
  SANTA_ROUTE = '/rules/query/santa'

  def testAdminGetList(self):
    """Admin retrieves list of all rules."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.QUERY_ROUTE)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertLen(output['content'], 3)

  def testAdminGetListWithPlatform(self):
    """Admin retrieves list of all rules with a platform."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.SANTA_ROUTE)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertLen(output['content'], 1)

  def testUserGetListNoPermissions(self):
    """Normal user attempts to retrieve all rules."""
    with self.LoggedInUser():
      self.testapp.get(self.QUERY_ROUTE, status=six.moves.http_client.FORBIDDEN)

  def testAdminGetQuery(self):
    """Admin queries a rule."""
    params = {'search': self.blockable2.key.id(),
              'searchBase': 'targetId'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.QUERY_ROUTE, params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertLen(output['content'], 2)

  def testAdminGetQueryWithPlatform(self):
    """Admin queries rules on a specific platform."""
    params = {'search': self.blockable2.key.id(),
              'searchBase': 'targetId'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.SANTA_ROUTE, params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertLen(output['content'], 1)

  def testUserGetQueryNoPermissions(self):
    """Normal user queries a rule."""
    params = {
        'search': self.blockable1.key.id(),
        'searchBase': 'targetId'}

    with self.LoggedInUser():
      self.testapp.get(
          self.QUERY_ROUTE, params, status=six.moves.http_client.FORBIDDEN)


class RuleHandler(RulesTest):

  ROUTE = '/rules/%s'

  def testAdminGet(self):
    """Admin gets a single rule by ID."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE % self.rule_1.key.urlsafe())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

  def testAdminGetBadKey(self):
    """Admin gets a single rule by a bad key."""
    with self.LoggedInUser(admin=True):
      self.testapp.get(
          self.ROUTE % 'BadKey', status=six.moves.http_client.BAD_REQUEST)

  def testAdminGetUnknownKey(self):
    """Admin gets a single rule by an unknown ID."""
    key = self.rule_3.key.urlsafe()
    self.rule_3.key.delete()
    with self.LoggedInUser(admin=True):
      self.testapp.get(self.ROUTE % key, status=six.moves.http_client.NOT_FOUND)

  def testUserGetNoPermissions(self):
    """User gets a single rule by ID."""
    with self.LoggedInUser():
      self.testapp.get(
          self.ROUTE % self.rule_1.key.id(),
          status=six.moves.http_client.FORBIDDEN)


if __name__ == '__main__':
  basetest.main()
