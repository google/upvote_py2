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

"""Unit tests for handlers.py."""

import httplib

import mock
import webapp2
from webob import exc

from common.testing import basetest

from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import handlers


class TestHandler(handlers.UpvoteRequestHandler):

  def get(self):
    self.response.status_int = httplib.OK

  def error(self, msg):
    self.abort(httplib.BAD_REQUEST, explanation=msg)


class UpvoteRequestHandlerTest(basetest.UpvoteTestCase):

  def setUp(self):
    self.app = webapp2.WSGIApplication([
        webapp2.Route(r'/err/<msg>', handler=TestHandler,
                      handler_method='error'),
        webapp2.Route(r'/', handler=TestHandler)])
    super(UpvoteRequestHandlerTest, self).setUp(wsgi_app=self.app)

  @mock.patch.object(TestHandler, 'RequestCounter',
                     new_callable=mock.PropertyMock)
  @mock.patch.object(TestHandler, 'get')
  def testHandleException_WithRequestCounter(self, mock_get, mock_grc):
    # Essentially what abort() does
    mock_get.side_effect = exc.HTTPBadRequest(explanation='foo')

    mock_metric = mock.Mock()
    mock_grc.return_value = mock_metric

    response = self.testapp.get('/', expect_errors=True)

    self.assertEqual(httplib.BAD_REQUEST, response.status_int)
    self.assertEqual('foo', response.body)
    self.assertEqual(1, mock_get.call_count)
    self.assertEqual(2, mock_grc.call_count)
    self.assertEqual(1, mock_metric.Increment.call_count)
    self.assertEqual(httplib.BAD_REQUEST, mock_metric.Increment.call_args[0][0])

  @mock.patch.object(TestHandler, 'get', side_effect=exc.HTTPBadRequest)
  def testHandleException_WithoutRequestCounter(self, mock_get):

    response = self.testapp.get('/', expect_errors=True)

    self.assertEqual(httplib.BAD_REQUEST, response.status_int)
    self.assertEqual(1, mock_get.call_count)

  @mock.patch.object(TestHandler, 'get', side_effect=exc.HTTPBadRequest)
  def testHandleException_WithoutExplanation(self, _):
    default_explanation = (
        'The server could not comply with the request since '
        'it is either malformed or otherwise incorrect.')

    response = self.testapp.get('/', expect_errors=True)

    self.assertEqual(default_explanation, response.body)

  @mock.patch.object(TestHandler, 'get', side_effect=KeyError)
  def testHandleException_ApplicationError(self, mock_get):

    response = self.testapp.get('/', expect_errors=True)

    self.assertEqual(httplib.INTERNAL_SERVER_ERROR, response.status_int)
    self.assertEqual(1, mock_get.call_count)

  @mock.patch.object(TestHandler, 'RequestCounter',
                     new_callable=mock.PropertyMock)
  @mock.patch.object(TestHandler, 'handle_exception')
  @mock.patch.object(TestHandler, 'dispatch')
  def testErrorHandling_UpvoteRequestHandler_WithRequestCounter(
      self, mock_dispatch, mock_handle_exception, mock_grc):

    # Mocking out the call to dispatch(), because any exceptions that occur
    # within the bulk of that method (or in an override of dispatch() by us, for
    # example, in BaseSantaApiHandler) aren't caught by the handle_exception()
    # method.
    # Rather, they bubble up to the WSGIApplication.error_handlers.
    mock_dispatch.side_effect = exc.HTTPForbidden
    mock_metric = mock.Mock()
    mock_grc.return_value = mock_metric

    response = self.testapp.get('/', expect_errors=True)

    self.assertEqual(httplib.FORBIDDEN, response.status_int)
    self.assertEqual(1, mock_dispatch.call_count)
    self.assertEqual(0, mock_handle_exception.call_count)
    self.assertEqual(1, mock_grc.call_count)
    self.assertEqual(1, mock_metric.Increment.call_count)
    self.assertEqual(httplib.FORBIDDEN, mock_metric.Increment.call_args[0][0])

  @mock.patch.object(handlers.UpvoteRequestHandler, 'handle_exception')
  @mock.patch.object(handlers.UpvoteRequestHandler, 'dispatch')
  def testErrorHandling_UpvoteRequestHandler_WithoutRequestCounter(
      self, mock_dispatch, mock_handle_exception):

    # Mocking out the call to dispatch(), because any exceptions that occur
    # within the bulk of that method (or in an override of dispatch() by us, for
    # example, in BaseSantaApiHandler) aren't caught by the handle_exception()
    # method. Rather, they bubble up to the WSGIApplication.error_handlers.
    mock_dispatch.side_effect = exc.HTTPForbidden

    response = self.testapp.get('/', expect_errors=True)

    self.assertEqual(httplib.FORBIDDEN, response.status_int)
    self.assertEqual(1, mock_dispatch.call_count)
    self.assertEqual(0, mock_handle_exception.call_count)

  def testErrorHandling_HandlerMethod(self):
    response = self.testapp.get('/err/Error Msg', expect_errors=True)

    # Verify that the intended error makes it through to the response, instead
    # of breakage within the error handling code resulting in a 500.
    self.assertEqual(httplib.BAD_REQUEST, response.status_int)
    self.assertEqual('Error Msg', response.body)

  def testErrorHandling_EscapeXss(self):
    msg = '<img onerror=\'alert("1")\'>'
    response = self.testapp.get('/err/%s' % msg, expect_errors=True)

    self.assertEqual(httplib.BAD_REQUEST, response.status_int)
    # Ensure the message is HTML escaped.
    self.assertNotEqual(msg, response.body)
    self.assertEqual(
        '&lt;img onerror=&#39;alert(&quot;1&quot;)&#39;&gt;',
        response.body)


if __name__ == '__main__':
  basetest.main()
