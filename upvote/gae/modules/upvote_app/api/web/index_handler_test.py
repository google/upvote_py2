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

"""Tests for the index_handler module."""

import httplib
import mock
import webapp2

from upvote.gae.lib.testing import basetest
from upvote.gae.modules.upvote_app.api.web import index_handler
from upvote.gae.shared.common import template_utils


class IndexHandlerTest(basetest.UpvoteTestCase):

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[
        index_handler.ADMIN_ROUTE, index_handler.USER_ROUTE])
    super(IndexHandlerTest, self).setUp(wsgi_app=app)

  @mock.patch.object(template_utils, 'GetTemplate')
  def testGetAdminConsole_AsAdmin(self, mock_get_template):

    with self.LoggedInUser(admin=True):
      self.testapp.get('/admin', status=httplib.OK)

    mock_get_template.assert_called_once_with(
        index_handler.IndexHandler.IndexPageVersion.ADMIN)

  @mock.patch.object(template_utils, 'GetTemplate')
  def testGetAdminConsole_AsUser(self, mock_get_template):

    with self.LoggedInUser(admin=False):
      self.testapp.get('/admin', status=httplib.FORBIDDEN)

    mock_get_template.assert_not_called()

  @mock.patch.object(template_utils, 'GetTemplate')
  def testGetBlockableList_AsAdmin(self, mock_get_template):

    with self.LoggedInUser(admin=True):
      self.testapp.get('/blockables', status=httplib.OK)

    mock_get_template.assert_called_once_with(
        index_handler.IndexHandler.IndexPageVersion.USER)

  @mock.patch.object(template_utils, 'GetTemplate')
  def testGetBlockableList_AsUser(self, mock_get_template):

    with self.LoggedInUser(admin=False):
      self.testapp.get('/blockables', status=httplib.OK)

    mock_get_template.assert_called_once_with(
        index_handler.IndexHandler.IndexPageVersion.USER)


if __name__ == '__main__':
  basetest.main()
