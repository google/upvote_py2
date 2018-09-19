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

"""Unit tests for base.py."""

import httplib

import mock
import webapp2
import webtest

from google.appengine.ext import ndb

from common.testing import basetest as gae_basetest
from upvote.gae.lib.testing import basetest
from upvote.gae.modules.upvote_app.api.web import base
from upvote.gae.shared.common import handlers
from upvote.gae.utils import xsrf_utils
from upvote.shared import constants


class MockHandler(base.BaseHandler):
  """Mock handler."""

  @base.RequireCapability(constants.PERMISSIONS.CHANGE_SETTINGS)
  def get(self):
    """Simple function to test RequireCapability decorator."""
    self.response.write('Content.')


class BaseTest(basetest.UpvoteTestCase):
  """Test Base Handler Class."""

  def setUp(self):
    app = webapp2.WSGIApplication([('/', MockHandler)])
    super(BaseTest, self).setUp(wsgi_app=app)

    self.PatchValidateXSRFToken()

  @base.RequireCapability(constants.PERMISSIONS.CHANGE_SETTINGS)
  def BadObject(self):
    """Test function to test non-handler call to decorator."""
    return 'This should not run.'

  @mock.patch.object(xsrf_utils, 'GenerateToken')
  def testAuthorityCheckPass(self, mock_generate_token):
    """Check if an admin is an admin."""
    mock_generate_token.return_value = 'token'
    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/')

    self.assertEqual(response.status_int, httplib.OK)
    self.assertEqual(response.body, 'Content.')
    mock_generate_token.assert_called_once_with()

  def testAuthorityCheckFail(self):
    """Check if a non-admin is an admin."""
    with self.LoggedInUser():
      response = self.testapp.get('/', status=httplib.FORBIDDEN)

    self.assertEqual(response.status_int, httplib.FORBIDDEN)

  def testAuthorityCheckWithBadObject(self):
    """Check for ValueError if passed a non-handler."""

    with self.assertRaises(ValueError):
      self.BadObject()


class BaseQueryHandlerTest(basetest.UpvoteTestCase):

  def testMetaclass_Success(self):
    class GoodQueryHandler(base.BaseQueryHandler):  # pylint: disable=unused-variable
      MODEL_CLASS = ndb.Model

  def testMetaclass_ModelClassOmitted(self):
    with self.assertRaises(NotImplementedError):

      class BadQueryHandler(base.BaseQueryHandler):  # pylint: disable=unused-variable
        pass

  def testMetaclass_ModelClassNotAModel(self):
    with self.assertRaises(NotImplementedError):

      class BadQueryHandler(base.BaseQueryHandler):  # pylint: disable=unused-variable
        # Not a ndb.Model
        MODEL_CLASS = BaseTest

  def testQueryModel_TranslatePropertyQuery(self):
    class Foo(ndb.Model):
      foo = ndb.StringProperty()

      @classmethod
      def TranslatePropertyQuery(cls, field, term):
        return 'foo', 'bar'

    class FooQueryHandler(base.BaseQueryHandler):
      MODEL_CLASS = Foo

    # Request a nonsense query to be ignored by TranslatePropertyQuery.
    with self.LoggedInUser():
      q = FooQueryHandler()._QueryModel({'bar': 'baz'})
    # Create an entity satisfying the translated query.
    Foo(foo='bar').put()
    # Ensure the translated query finds the created entity.
    self.assertIsNotNone(q.get())

  def testQueryModel_TranslatePropertyQuery_NotPresent(self):
    class Foo(ndb.Model):
      foo = ndb.StringProperty()

    class FooQueryHandler(base.BaseQueryHandler):
      MODEL_CLASS = Foo

    # Ensure that, without the translation mechanism defined, a bogus query will
    # raise an error.
    with self.assertRaises(base.QueryError):
      with self.LoggedInUser():
        FooQueryHandler()._QueryModel({'bar': 'baz'})


if __name__ == '__main__':
  basetest.main()
