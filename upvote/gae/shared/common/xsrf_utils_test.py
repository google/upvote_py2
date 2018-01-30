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

"""Tests for XSRF protection middleware."""

import httplib
import os

import mock
from oauth2client.contrib import xsrfutil
import webapp2

from google.appengine.api import users
from absl.testing import absltest

from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import user_map
from upvote.gae.shared.common import xsrf_utils


class FakeHandler(webapp2.RequestHandler):
  """Fake request handler."""

  def __init__(self, request, response):
    webapp2.RequestHandler.__init__(self, request, response)
    self.called = False

  @xsrf_utils.RequireToken
  def post(self):
    self.called = True
    self.response.write('called')


class XsrfTest(basetest.UpvoteTestCase):

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(r'', handler=FakeHandler)])
    super(XsrfTest, self).setUp(app, patch_generate_token=False)
    self.user_email = user_map.UsernameToEmail('test')
    self.Login(self.user_email)
    self.user_id = users.get_current_user().user_id()

  @mock.patch.object(os, 'urandom', return_value='foo'*4)
  def testNewXsrfSecret(self, mock_urandom):
    xsrf_utils.SiteXsrfSecret.GetInstance().key.delete()
    self.assertEqual('foofoofoofoo', xsrf_utils.SiteXsrfSecret.GetSecret())

  @mock.patch.object(xsrfutil, 'generate_token')
  def testGenerateToken(self, mock_generate_token):
    token = xsrf_utils.GenerateToken()
    mock_generate_token.assert_called_once_with(
        self.secret_key, self.user_id,
        action_id=xsrf_utils._UPVOTE_DEFAULT_ACTION_ID)
    self.assertEquals(mock_generate_token.return_value, token)

  def testRequireToken_ValidRequest(self):
    token = xsrf_utils.GenerateToken()
    response = self.testapp.post('', {}, {'X-XSRF-TOKEN': token})

    self.assertEquals(httplib.OK, response.status_int)
    self.assertEquals('called', response.body)

  def testRequireToken_RequestMissesToken(self):
    response = self.testapp.post('', expect_errors=True)

    self.assertEquals(httplib.FORBIDDEN, response.status_int)

  def testRequireToken_RequestWrongToken(self):
    response = self.testapp.post(
        '', {}, {'X-XSRF-TOKEN': 'fake token'}, expect_errors=True)

    self.assertEquals(httplib.FORBIDDEN, response.status_int)

  def testUnauthenticatedUser_BlankToken(self):
    self.Logout()
    with self.assertRaises(xsrf_utils.UserNotFoundError):
      self.assertEqual('', xsrf_utils.GenerateToken())


if __name__ == '__main__':
  absltest.main()
