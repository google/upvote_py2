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

  @mock.patch.object(template_utils, 'GetTemplate')
  def testGetAdmin(self, mock_get_template):
    mock_get_template.return_value.render.return_value = 'content'
    handler = index_handler.IndexHandler(
        webapp2.Request.blank('/admin/'), webapp2.Response())
    handler.GetAdmin()
    mock_get_template.assert_called_once_with(
        index_handler.IndexHandler.IndexPageVersion.ADMIN)
    self.assertEqual(httplib.OK, handler.response.status_int)
    self.assertEqual('content', handler.response.body)

  @mock.patch.object(template_utils, 'GetTemplate')
  def testGetUser(self, mock_get_template):
    mock_get_template.return_value.render.return_value = 'content'
    handler = index_handler.IndexHandler(
        webapp2.Request.blank('/admin/'), webapp2.Response())
    handler.GetUser()
    mock_get_template.assert_called_once_with(
        index_handler.IndexHandler.IndexPageVersion.USER)
    self.assertEqual(httplib.OK, handler.response.status_int)
    self.assertEqual('content', handler.response.body)


if __name__ == '__main__':
  basetest.main()
