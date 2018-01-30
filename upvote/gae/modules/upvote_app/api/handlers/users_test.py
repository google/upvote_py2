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
import json

import webapp2

from upvote.gae.modules.upvote_app.api.handlers import users
from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import user_map
from upvote.gae.shared.models import base
from upvote.gae.shared.models import test_utils
from upvote.shared import constants


class UsersTest(basetest.UpvoteTestCase):
  """Base class for User handler tests."""

  def setUp(self, app):
    super(UsersTest, self).setUp(wsgi_app=app)

    self.PatchValidateXSRFToken()


class UserQueryHandlerTest(UsersTest):

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(r'', handler=users.UserQueryHandler)])
    super(UserQueryHandlerTest, self).setUp(app)

  def testAdminGetList(self):
    """Admin retrieves list of all users."""

    user_count = 10
    test_utils.CreateUsers(user_count)

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('')

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(user_count, len(output['content']))

  def testAdminGetListPlatformNoEffect(self):
    """Admin specifies a platform which has no effect on the results."""
    params = {'platform': 'santa'}

    user_count = 10
    test_utils.CreateUsers(user_count)

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('', params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(user_count, len(output['content']))

  def testUserGetListNoPermissions(self):
    """Normal user attempts to retrieve all users."""
    with self.LoggedInUser():
      self.testapp.get('', status=httplib.FORBIDDEN)

  def testAdminGetQuery(self):
    """Admin queries a user."""
    params = {'search': 1, 'searchBase': 'voteWeight'}

    user_count = 10
    test_utils.CreateUsers(user_count)

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('', params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(user_count, len(output['content']))

  def testUserGetQueryNoPermissions(self):
    """Normal user queries a rule."""
    params = {'search': 1, 'searchBase': 'voteWeight'}

    with self.LoggedInUser():
      self.testapp.get('', params, status=httplib.FORBIDDEN)


class UserHandlerTest(UsersTest):

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(r'/<user_id>', handler=users.UserHandler)])
    super(UserHandlerTest, self).setUp(app)

  def testAdminGetSelf(self):
    """Admin getting own information."""
    with self.LoggedInUser(admin=True) as admin:
      response = self.testapp.get('/' + admin.email)

      output = response.json

      self.assertIn('application/json', response.headers['Content-type'])
      self.assertIsInstance(output, dict)
      self.assertTrue(output['isAdmin'])
      self.assertEqual(output['name'], admin.nickname)

  def testAdminGetOtherUser(self):
    """Admin getting information on another user."""
    user = test_utils.CreateUser()
    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/' + user.email)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertFalse(output['isAdmin'])
    self.assertEqual(output['name'], user.nickname)

  def testAdminGetUnknownUser(self):
    """Admin attempting to get information on an unknown user."""
    with self.LoggedInUser(admin=True):
      unknown_user = user_map.UsernameToEmail('blahblahblah')
      self.testapp.get('/' + unknown_user, status=httplib.NOT_FOUND)

  def testUserGetOtherUser(self):
    """Normal user trying to get information on another user."""
    user = test_utils.CreateUser()
    with self.LoggedInUser():
      self.testapp.get('/' + user.email, status=httplib.FORBIDDEN)

  def testAdminEditUser(self):
    """Admin editing an existing user through post request."""
    params = {'roles': constants.USER_ROLE.TRUSTED_USER}
    user = test_utils.CreateUser()

    with self.LoggedInUser(admin=True):
      response = self.testapp.post('/' + user.email, params)

    expected_dict = {'roles': [constants.USER_ROLE.TRUSTED_USER]}

    datastore_user_dict = (base.User.get_by_id(user.email).to_dict())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertDictContainsSubset(expected_dict, output)
    self.assertDictContainsSubset(expected_dict, datastore_user_dict)

  def testAdminAddingUser(self):
    """Admin adding a user through a post request."""
    id_ = user_map.UsernameToEmail('user4')
    pre_post_user = base.User.get_by_id(id_)

    pre_post_user_existed = (pre_post_user is not None)

    params = {'roles': constants.USER_ROLE.TRUSTED_USER}

    with self.LoggedInUser(admin=True):
      response = self.testapp.post('/' + id_, params)

    expected_dict = {'id': id_, 'roles': [constants.USER_ROLE.TRUSTED_USER]}

    datastore_user = base.User.get_by_id(id_)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertDictContainsSubset(expected_dict, output)
    self.assertDictContainsSubset(expected_dict, datastore_user.to_dict())
    self.assertFalse(pre_post_user_existed)

  def testNormalUserEditUserAttempt(self):
    """Normal user tries to edit an existing user."""
    raw_params = {'roles': [constants.USER_ROLE.ADMINISTRATOR]}

    params = json.dumps(raw_params)

    with self.LoggedInUser() as user:
      self.testapp.post('/' + user.email, params, status=httplib.FORBIDDEN)


if __name__ == '__main__':
  basetest.main()
