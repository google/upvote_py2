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

"""Tests for the index module."""

import httplib
import mock
import webapp2

from upvote.gae.lib.testing import basetest
from upvote.gae.modules.upvote_app.api.web import index


class FakeIndexHandler(index.IndexHandler):

  TEMPLATE_NAME = 'whatever.html'

  def get(self):
    return self._Get()


class IndexHandlerTest(basetest.UpvoteTestCase):

  def setUp(self):
    route = webapp2.Route('/stuff', handler=FakeIndexHandler)
    app = webapp2.WSGIApplication(routes=[route])
    super(IndexHandlerTest, self).setUp(wsgi_app=app)

  @mock.patch.object(index.template_utils, 'GetTemplate')
  def testDebug_On(self, mock_get_template):

    mock_template = mock.Mock()
    mock_get_template.return_value = mock_template

    with self.LoggedInUser():
      self.testapp.get('/stuff?debug=1')

    mock_template.render.assert_called_once()
    actual_context = mock_template.render.call_args_list[0][0][0]
    self.assertTrue(actual_context['debug'])

  @mock.patch.object(index.template_utils, 'GetTemplate')
  def testDebug_Off(self, mock_get_template):

    mock_template = mock.Mock()
    mock_get_template.return_value = mock_template

    with self.LoggedInUser():
      self.testapp.get('/stuff?debug=0')

    mock_template.render.assert_called_once()
    actual_context = mock_template.render.call_args_list[0][0][0]
    self.assertFalse(actual_context['debug'])

  @mock.patch.object(index.template_utils, 'GetTemplate')
  def testDebug_Omitted(self, mock_get_template):

    mock_template = mock.Mock()
    mock_get_template.return_value = mock_template

    with self.LoggedInUser():
      self.testapp.get('/stuff')

    mock_template.render.assert_called_once()
    actual_context = mock_template.render.call_args_list[0][0][0]
    self.assertFalse(actual_context['debug'])

  @mock.patch.object(index.template_utils, 'GetTemplate')
  def testDebug_BadValue(self, mock_get_template):

    mock_template = mock.Mock()
    mock_get_template.return_value = mock_template

    with self.LoggedInUser():
      self.testapp.get('/stuff?debug=asdf')

    mock_template.render.assert_called_once()
    actual_context = mock_template.render.call_args_list[0][0][0]
    self.assertFalse(actual_context['debug'])


class AdminIndexHandlerTest(basetest.UpvoteTestCase):

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[index.ADMIN_ROUTE])
    super(AdminIndexHandlerTest, self).setUp(wsgi_app=app)

  @mock.patch.object(index.template_utils, 'GetTemplate')
  def testGet_AsAdmin_TrailingSlash(self, mock_get_template):

    with self.LoggedInUser(admin=True):
      self.testapp.get('/admin/', status=httplib.OK)

    mock_get_template.assert_called_once_with(
        index.AdminIndexHandler.TEMPLATE_NAME)

  @mock.patch.object(index.template_utils, 'GetTemplate')
  def testGet_AsAdmin_NoTrailingSlash(self, mock_get_template):

    with self.LoggedInUser(admin=True):
      self.testapp.get('/admin', status=httplib.OK)

    mock_get_template.assert_called_once_with(
        index.AdminIndexHandler.TEMPLATE_NAME)

  @mock.patch.object(index.template_utils, 'GetTemplate')
  def testGet_AsUser(self, mock_get_template):

    with self.LoggedInUser(admin=False):
      self.testapp.get('/admin', status=httplib.FORBIDDEN)

    mock_get_template.assert_not_called()


class UserIndexHandlerTest(basetest.UpvoteTestCase):

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[index.USER_ROUTE])
    super(UserIndexHandlerTest, self).setUp(wsgi_app=app)

  @mock.patch.object(index.template_utils, 'GetTemplate')
  def testGetRoot(self, mock_get_template):

    with self.LoggedInUser(admin=False):
      self.testapp.get('/', status=httplib.OK)

    mock_get_template.assert_called_once_with(
        index.UserIndexHandler.TEMPLATE_NAME)

  @mock.patch.object(index.template_utils, 'GetTemplate')
  def testGetBlockableList(self, mock_get_template):

    with self.LoggedInUser(admin=False):
      self.testapp.get('/blockables', status=httplib.OK)

    mock_get_template.assert_called_once_with(
        index.UserIndexHandler.TEMPLATE_NAME)


if __name__ == '__main__':
  basetest.main()
