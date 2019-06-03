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

"""Unit tests for handler_utils.py."""

import mock
import six.moves.http_client
import webapp2
from webob import exc
import webtest

from google.appengine.ext import ndb
from common.testing import basetest as gae_basetest
from upvote.gae.lib.testing import basetest
from upvote.gae.utils import handler_utils
from upvote.gae.utils import xsrf_utils
from upvote.shared import constants


class FakeUpvoteRequestHandler(handler_utils.UpvoteRequestHandler):

  def get(self):
    self.response.status_int = six.moves.http_client.OK

  def error(self, msg):
    self.abort(six.moves.http_client.BAD_REQUEST, explanation=msg)


class UpvoteRequestHandlerTest(basetest.UpvoteTestCase):

  def setUp(self):
    self.app = webapp2.WSGIApplication([
        webapp2.Route(r'/err/<msg>', handler=FakeUpvoteRequestHandler,
                      handler_method='error'),
        webapp2.Route(r'/', handler=FakeUpvoteRequestHandler)])
    super(UpvoteRequestHandlerTest, self).setUp(wsgi_app=self.app)

  @mock.patch.object(FakeUpvoteRequestHandler, 'RequestCounter',
                     new_callable=mock.PropertyMock)
  @mock.patch.object(FakeUpvoteRequestHandler, 'get')
  def testHandleException_WithRequestCounter(self, mock_get, mock_grc):
    # Essentially what abort() does
    mock_get.side_effect = exc.HTTPBadRequest(explanation='foo')

    mock_metric = mock.Mock()
    mock_grc.return_value = mock_metric

    response = self.testapp.get('/', expect_errors=True)

    self.assertEqual(six.moves.http_client.BAD_REQUEST, response.status_int)
    self.assertEqual('foo', response.body)
    self.assertEqual(1, mock_get.call_count)
    self.assertEqual(2, mock_grc.call_count)
    self.assertEqual(1, mock_metric.Increment.call_count)
    self.assertEqual(six.moves.http_client.BAD_REQUEST,
                     mock_metric.Increment.call_args[0][0])

  @mock.patch.object(
      FakeUpvoteRequestHandler, 'get', side_effect=exc.HTTPBadRequest)
  def testHandleException_WithoutRequestCounter(self, mock_get):

    response = self.testapp.get('/', expect_errors=True)

    self.assertEqual(six.moves.http_client.BAD_REQUEST, response.status_int)
    self.assertEqual(1, mock_get.call_count)

  @mock.patch.object(
      FakeUpvoteRequestHandler, 'get', side_effect=exc.HTTPBadRequest)
  def testHandleException_WithoutExplanation(self, _):
    default_explanation = (
        'The server could not comply with the request since '
        'it is either malformed or otherwise incorrect.')

    response = self.testapp.get('/', expect_errors=True)

    self.assertEqual(default_explanation, response.body)

  @mock.patch.object(FakeUpvoteRequestHandler, 'get', side_effect=KeyError)
  def testHandleException_ApplicationError(self, mock_get):

    response = self.testapp.get('/', expect_errors=True)

    self.assertEqual(six.moves.http_client.INTERNAL_SERVER_ERROR,
                     response.status_int)
    self.assertEqual(1, mock_get.call_count)

  @mock.patch.object(FakeUpvoteRequestHandler, 'RequestCounter',
                     new_callable=mock.PropertyMock)
  @mock.patch.object(FakeUpvoteRequestHandler, 'handle_exception')
  @mock.patch.object(FakeUpvoteRequestHandler, 'dispatch')
  def testErrorHandling_UpvoteRequestHandler_WithRequestCounter(
      self, mock_dispatch, mock_handle_exception, mock_grc):

    # Mocking out the call to dispatch(), because any exceptions that occur
    # within the bulk of that method (or in an override of dispatch() by us, for
    # example, in SantaRequestHandler) aren't caught by the handle_exception()
    # method.
    # Rather, they bubble up to the WSGIApplication.error_handlers.
    mock_dispatch.side_effect = exc.HTTPForbidden
    mock_metric = mock.Mock()
    mock_grc.return_value = mock_metric

    response = self.testapp.get('/', expect_errors=True)

    self.assertEqual(six.moves.http_client.FORBIDDEN, response.status_int)
    self.assertEqual(1, mock_dispatch.call_count)
    self.assertEqual(0, mock_handle_exception.call_count)
    self.assertEqual(1, mock_grc.call_count)
    self.assertEqual(1, mock_metric.Increment.call_count)
    self.assertEqual(six.moves.http_client.FORBIDDEN,
                     mock_metric.Increment.call_args[0][0])

  @mock.patch.object(handler_utils.UpvoteRequestHandler, 'handle_exception')
  @mock.patch.object(handler_utils.UpvoteRequestHandler, 'dispatch')
  def testErrorHandling_UpvoteRequestHandler_WithoutRequestCounter(
      self, mock_dispatch, mock_handle_exception):

    # Mocking out the call to dispatch(), because any exceptions that occur
    # within the bulk of that method (or in an override of dispatch() by us, for
    # example, in SantaRequestHandler) aren't caught by the handle_exception()
    # method. Rather, they bubble up to the WSGIApplication.error_handlers.
    mock_dispatch.side_effect = exc.HTTPForbidden

    response = self.testapp.get('/', expect_errors=True)

    self.assertEqual(six.moves.http_client.FORBIDDEN, response.status_int)
    self.assertEqual(1, mock_dispatch.call_count)
    self.assertEqual(0, mock_handle_exception.call_count)

  def testErrorHandling_HandlerMethod(self):
    response = self.testapp.get('/err/Error Msg', expect_errors=True)

    # Verify that the intended error makes it through to the response, instead
    # of breakage within the error handling code resulting in a 500.
    self.assertEqual(six.moves.http_client.BAD_REQUEST, response.status_int)
    self.assertEqual('Error Msg', response.body)

  def testErrorHandling_EscapeXss(self):
    msg = '<img onerror=\'alert("1")\'>'
    response = self.testapp.get('/err/%s' % msg, expect_errors=True)

    self.assertEqual(six.moves.http_client.BAD_REQUEST, response.status_int)
    # Ensure the message is HTML escaped.
    self.assertNotEqual(msg, response.body)
    self.assertEqual(
        '&lt;img onerror=&#x27;alert(&quot;1&quot;)&#x27;&gt;',
        response.body)


class FakeCronJobHandler(handler_utils.CronJobHandler):

  def get(self):
    self.response.status_int = six.moves.http_client.OK


class CronJobHandlerTest(basetest.UpvoteTestCase):

  def setUp(self):
    route = webapp2.Route('/do-cron-thing', handler=FakeCronJobHandler)
    wsgi_app = webapp2.WSGIApplication(routes=[route])
    super(CronJobHandlerTest, self).setUp(wsgi_app=wsgi_app)

  def testHeaderMissing(self):
    self.Logout()  # Ensure there's not a human logged in.
    self.testapp.get('/do-cron-thing', status=six.moves.http_client.FORBIDDEN)

  def testSuccess(self):
    self.Logout()  # Ensure there's not a human logged in.
    self.testapp.get(
        '/do-cron-thing',
        headers={'X-AppEngine-Cron': 'true'},
        status=six.moves.http_client.OK)


class FakeUserFacingHandler(handler_utils.UserFacingHandler):

  @handler_utils.RequirePermission(constants.PERMISSIONS.CHANGE_SETTINGS)
  def get(self):
    """Simple function to test RequirePermission decorator."""
    self.response.write('Content.')


class UserFacingHandlerTest(basetest.UpvoteTestCase):

  def setUp(self):
    app = webapp2.WSGIApplication([('/', FakeUserFacingHandler)])
    super(UserFacingHandlerTest, self).setUp(wsgi_app=app)
    self.PatchValidateXSRFToken()

  @handler_utils.RequirePermission(constants.PERMISSIONS.CHANGE_SETTINGS)
  def BadObject(self):
    """Test function to test non-handler call to decorator."""
    return 'This should not run.'

  @mock.patch.object(xsrf_utils, 'GenerateToken')
  def testAuthorityCheckPass(self, mock_generate_token):
    """Check if an admin is an admin."""
    mock_generate_token.return_value = 'token'
    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/')

    self.assertEqual(response.status_int, six.moves.http_client.OK)
    self.assertEqual(response.body, 'Content.')
    mock_generate_token.assert_called_once_with()

  def testAuthorityCheckFail(self):
    """Check if a non-admin is an admin."""
    with self.LoggedInUser():
      response = self.testapp.get('/', status=six.moves.http_client.FORBIDDEN)

    self.assertEqual(response.status_int, six.moves.http_client.FORBIDDEN)

  def testAuthorityCheckWithBadObject(self):
    """Check for ValueError if passed a non-handler."""

    with self.assertRaises(ValueError):
      self.BadObject()


class UserFacingQueryHandlerTest(basetest.UpvoteTestCase):

  def testMetaclass_Success(self):
    class GoodQueryHandler(handler_utils.UserFacingQueryHandler):  # pylint: disable=unused-variable
      MODEL_CLASS = ndb.Model

  def testMetaclass_ModelClassOmitted(self):
    with self.assertRaises(NotImplementedError):

      class BadQueryHandler(handler_utils.UserFacingQueryHandler):  # pylint: disable=unused-variable
        pass

  def testMetaclass_ModelClassNotAModel(self):
    with self.assertRaises(NotImplementedError):

      class BadQueryHandler(handler_utils.UserFacingQueryHandler):  # pylint: disable=unused-variable
        # Not a ndb.Model
        MODEL_CLASS = UserFacingHandlerTest

  def testQueryModel_TranslatePropertyQuery(self):
    class Foo(ndb.Model):
      foo = ndb.StringProperty()

      @classmethod
      def TranslatePropertyQuery(cls, field, term):
        return 'foo', 'bar'

    class FooQueryHandler(handler_utils.UserFacingQueryHandler):
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

    class FooQueryHandler(handler_utils.UserFacingQueryHandler):
      MODEL_CLASS = Foo

    # Ensure that, without the translation mechanism defined, a bogus query will
    # raise an error.
    with self.assertRaises(handler_utils.QueryError):
      with self.LoggedInUser():
        FooQueryHandler()._QueryModel({'bar': 'baz'})


class FakeAdminOnlyHandler(handler_utils.AdminOnlyHandler):

  def get(self):
    self.response.status_int = six.moves.http_client.OK


class AdminOnlyHandlerTest(basetest.UpvoteTestCase):

  def setUp(self):
    route = webapp2.Route('/do-admin-thing', handler=FakeAdminOnlyHandler)
    wsgi_app = webapp2.WSGIApplication(routes=[route])
    super(AdminOnlyHandlerTest, self).setUp(wsgi_app=wsgi_app)

  def testUser(self):
    with self.LoggedInUser():
      self.testapp.get(
          '/do-admin-thing', status=six.moves.http_client.FORBIDDEN)

  def testAdmin(self):
    with self.LoggedInUser(admin=True):
      self.testapp.get('/do-admin-thing', status=six.moves.http_client.OK)


if __name__ == '__main__':
  basetest.main()
