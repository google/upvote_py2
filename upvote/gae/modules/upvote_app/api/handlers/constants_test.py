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

"""Tests for Constant handler."""

import httplib
import webapp2

from upvote.gae.lib.testing import basetest
from upvote.gae.modules.upvote_app.api.handlers import constants
from upvote.shared import constants as common_constants


class ConstantTest(basetest.UpvoteTestCase):
  """Test Constant handler class."""

  ROUTE = '/constants/%s'

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[constants.ROUTES])
    super(ConstantTest, self).setUp(wsgi_app=app)

  def testGetExisting(self):
    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE % 'userrole')
    # Quick and dirty way to make sure everything is all unicoded up.
    unicode_elems = map(unicode, common_constants.USER_ROLE.SET_ALL)
    self.assertIn(u'UserRole', response.json)
    self.assertItemsEqual(response.json[u'UserRole'], unicode_elems)

  def testGetExistingNoPermission(self):
    with self.LoggedInUser():
      response = self.testapp.get(
          self.ROUTE % 'userrole', status=httplib.FORBIDDEN)

    self.assertEqual(response.status_int, httplib.FORBIDDEN)

  def testGetNoExisting(self):
    with self.LoggedInUser(admin=True):
      response = self.testapp.get(
          self.ROUTE % 'DoesntExist', status=httplib.NOT_FOUND)

    self.assertEqual(response.status_int, httplib.NOT_FOUND)


if __name__ == '__main__':
  basetest.main()
