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

"""Unit tests for users.py."""

import httplib

import webapp2

from upvote.gae.datastore import test_utils
from upvote.gae.lib.testing import basetest
from upvote.gae.modules.upvote_app.api.web import users
from upvote.gae.utils import user_utils


class UsersTest(basetest.UpvoteTestCase):
  """Base class for User handler tests."""

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[users.ROUTES])
    super(UsersTest, self).setUp(wsgi_app=app)

    self.PatchValidateXSRFToken()


class UserQueryHandlerTest(UsersTest):

  ROUTE = '/users/query'

  def testAdminGetList(self):
    """Admin retrieves list of all users."""

    user_count = 10
    test_utils.CreateUsers(user_count)

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertLen(output['content'], user_count)

  def testAdminGetListPlatformNoEffect(self):
    """Admin specifies a platform which has no effect on the results."""
    params = {'platform': 'santa'}

    user_count = 10
    test_utils.CreateUsers(user_count)

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE, params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertLen(output['content'], user_count)

  def testUserGetListNoPermissions(self):
    """Normal user attempts to retrieve all users."""
    with self.LoggedInUser():
      self.testapp.get(self.ROUTE, status=httplib.FORBIDDEN)

  def testAdminGetQuery(self):
    """Admin queries a user."""
    params = {'search': 1, 'searchBase': 'voteWeight'}

    user_count = 10
    test_utils.CreateUsers(user_count)

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE, params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertLen(output['content'], user_count)

  def testUserGetQueryNoPermissions(self):
    """Normal user queries a rule."""
    params = {'search': 1, 'searchBase': 'voteWeight'}

    with self.LoggedInUser():
      self.testapp.get(self.ROUTE, params, status=httplib.FORBIDDEN)


class UserHandlerTest(UsersTest):

  ROUTE = '/users/%s'

  def testAdminGetSelf(self):
    """Admin getting own information."""
    with self.LoggedInUser(admin=True) as admin:
      response = self.testapp.get(self.ROUTE % admin.email)

      output = response.json

      self.assertIn('application/json', response.headers['Content-type'])
      self.assertIsInstance(output, dict)
      self.assertTrue(output['isAdmin'])
      self.assertEqual(output['name'], admin.nickname)

  def testAdminGetOtherUser(self):
    """Admin getting information on another user."""
    user = test_utils.CreateUser()
    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE % user.email)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertFalse(output['isAdmin'])
    self.assertEqual(output['name'], user.nickname)

  def testAdminGetUnknownUser(self):
    """Admin attempting to get information on an unknown user."""
    with self.LoggedInUser(admin=True):
      unknown_user = user_utils.UsernameToEmail('blahblahblah')
      self.testapp.get(self.ROUTE % unknown_user, status=httplib.NOT_FOUND)

  def testUserGetOtherUser(self):
    """Normal user trying to get information on another user."""
    user = test_utils.CreateUser()
    with self.LoggedInUser():
      self.testapp.get(self.ROUTE % user.email, status=httplib.FORBIDDEN)


if __name__ == '__main__':
  basetest.main()
