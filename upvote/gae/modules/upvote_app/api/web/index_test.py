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

import mock
import six.moves.http_client
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

  @mock.patch.object(index.template_utils, 'RenderWebTemplate')
  def testDebug_On(self, mock_render):

    with self.LoggedInUser():
      self.testapp.get('/stuff?debug=1')

    mock_render.assert_called_once_with(
        'whatever.html', debug=True, username=mock.ANY)

  @mock.patch.object(index.template_utils, 'RenderWebTemplate')
  def testDebug_Off(self, mock_render):

    with self.LoggedInUser():
      self.testapp.get('/stuff?debug=0')

    mock_render.assert_called_once_with(
        'whatever.html', debug=False, username=mock.ANY)

  @mock.patch.object(index.template_utils, 'RenderWebTemplate')
  def testDebug_Omitted(self, mock_render):

    with self.LoggedInUser():
      self.testapp.get('/stuff')

    mock_render.assert_called_once_with(
        'whatever.html', debug=False, username=mock.ANY)

  @mock.patch.object(index.template_utils, 'RenderWebTemplate')
  def testDebug_BadValue(self, mock_render):

    with self.LoggedInUser():
      self.testapp.get('/stuff?debug=asdf')

    mock_render.assert_called_once_with(
        'whatever.html', debug=False, username=mock.ANY)


class AdminIndexHandlerTest(basetest.UpvoteTestCase):

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[index.ADMIN_ROUTE])
    super(AdminIndexHandlerTest, self).setUp(wsgi_app=app)

  @mock.patch.object(index.template_utils, 'RenderWebTemplate')
  def testGet_AsAdmin_TrailingSlash(self, mock_render):

    with self.LoggedInUser(admin=True):
      self.testapp.get('/admin/', status=six.moves.http_client.OK)

    mock_render.assert_called_once_with(
        index.AdminIndexHandler.TEMPLATE_NAME, debug=False, username=mock.ANY)

  @mock.patch.object(index.template_utils, 'RenderWebTemplate')
  def testGet_AsAdmin_NoTrailingSlash(self, mock_render):

    with self.LoggedInUser(admin=True):
      self.testapp.get('/admin', status=six.moves.http_client.OK)

    mock_render.assert_called_once_with(
        index.AdminIndexHandler.TEMPLATE_NAME, debug=False, username=mock.ANY)

  @mock.patch.object(index.template_utils, 'RenderWebTemplate')
  def testGet_AsUser(self, mock_render):

    with self.LoggedInUser(admin=False):
      self.testapp.get('/admin', status=six.moves.http_client.FORBIDDEN)

    mock_render.assert_not_called()


class UserIndexHandlerTest(basetest.UpvoteTestCase):

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[index.USER_ROUTE])
    super(UserIndexHandlerTest, self).setUp(wsgi_app=app)

  @mock.patch.object(index.template_utils, 'RenderWebTemplate')
  def testGetRoot(self, mock_render):

    with self.LoggedInUser(admin=False):
      self.testapp.get('/', status=six.moves.http_client.OK)

    mock_render.assert_called_once_with(
        index.UserIndexHandler.TEMPLATE_NAME, debug=False, username=mock.ANY)

  @mock.patch.object(index.template_utils, 'RenderWebTemplate')
  def testGetBlockableList(self, mock_render):

    with self.LoggedInUser(admin=False):
      self.testapp.get('/blockables', status=six.moves.http_client.OK)

    mock_render.assert_called_once_with(
        index.UserIndexHandler.TEMPLATE_NAME, debug=False, username=mock.ANY)


if __name__ == '__main__':
  basetest.main()
