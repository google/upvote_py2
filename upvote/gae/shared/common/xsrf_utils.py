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

"""Middleware for handling XSRF protection.


Contains methods and decorators for generating and validating XSRF tokens.

Angular has built in functionality to handle XSRF protection. The server
should generate the XSRF token and set it into the cookie named 'XSRF-TOKEN'.
On POST requests, the client (Angular) sets the token value in a header named
'X-XSRF-TOKEN' which the server then validates.

Usage:
@xsrf_utils.RequireToken
def post()
"""
import datetime
import functools
import httplib
import logging
import os

from oauth2client.contrib import xsrfutil

from google.appengine.api import users
from google.appengine.ext import ndb

from upvote.gae.datastore import utils

# Token timeout in microseconds.
xsrfutil.DEFAULT_TIMEOUT_SECS = (
    datetime.timedelta(hours=3, minutes=55).total_seconds() * 1000000)
# Action ID is an identifier of the action that callers requested authorization
# for. As default, Upvote uses the following action id.
_UPVOTE_DEFAULT_ACTION_ID = 'upvote_default_action'
DEFAULT_HEADER = 'X-XSRF-TOKEN'

# Angular uses the following name of cookie for anti-XSRF token.
ANGULAR_XSRF_COOKIE_NAME = 'XSRF-TOKEN'


class Error(Exception):
  """Base error class for this module."""


class TokenInvalidError(Error):
  """Error raised if the token could not be validated."""


class UserNotFoundError(Error):
  """Error raised if the user identifier cannot be determined."""


class SiteXsrfSecret(utils.Singleton):
  """A model for storing the site's xsrf key."""
  secret = ndb.StringProperty()

  @classmethod
  def GetSecret(cls):
    inst = super(SiteXsrfSecret, cls).GetInstance()
    if inst is None:
      # The secret length should match the block size of the hash function.
      inst = cls.SetInstance(secret=os.urandom(64).encode('hex'))
    return inst.secret.decode('hex')


def _GetCurrentUserId():
  """Returns the user ID of the logged-in user.

  Returns:
    The user ID of the logged-in user. Must be associated with a Google account.

  Raises:
    UserNotFoundError: If the user is not logged in or not associated with a
        Google account.
  """
  user = users.get_current_user()
  try:
    user_id = user.user_id()
  except AttributeError:
    raise UserNotFoundError('The user is not signed in.')
  else:
    if not user_id:
      raise UserNotFoundError(
          'The user_id is empty or None. Verify that the user is associated '
          'with a Google account.')
  return user_id


def GenerateToken(action_id=_UPVOTE_DEFAULT_ACTION_ID, user_id=None):
  """Generates a string XSRF token.

  Args:
    action_id: A string identifying the action being performed.
    user_id: A string identifying the user, defaults to the current logged-in
        user.

  Returns:
    A string XSRF token.
  """
  if not user_id:
    user_id = _GetCurrentUserId()
  return xsrfutil.generate_token(
      SiteXsrfSecret.GetSecret(), user_id, action_id=action_id)


def ValidateToken(token, action_id=_UPVOTE_DEFAULT_ACTION_ID, user_id=None):
  """Validates a string XSRF token.

  Args:
    token: The token to validate.
    action_id: A string identifying the action being performed.
    user_id: The 'user' the token is associated with. If none, the current
        user is used.

  Raises:
    UserNotFoundError: user not logged in or not associated with
        a Google account.
    TokenInvalidError: the supplied token is not valid.
  """
  try:
    if not user_id:
      user_id = _GetCurrentUserId()
  except UserNotFoundError as err:
    logging.error('Error encountered: %s', repr(err))
    raise
  else:
    success = xsrfutil.validate_token(
        SiteXsrfSecret.GetSecret(), token, user_id, action_id=action_id)
    if not success:
      logging.error('Token failed to validate')
      raise TokenInvalidError()


def RequireToken(method):
  """Decorator to verify a XSRF token passed to a webapp2.RequestHandler method.

  The first argument to the decorated method must be a webapp2.RequestHandler
  instance. Usually the decorator is applied to a webapp2.RequestHandler.post
  method, so the first argument is 'self'.

  Args:
    method: A method (e.g. post) whose first argument is a
        webapp2.RequestHandler.

  Returns:
    The decorated method.
  """
  @functools.wraps(method)
  def RequireTokenWrapper(handler, *args, **kwargs):
    # Get the XSRF token from the request, or an empty string if not found.
    token = handler.request.headers.get(DEFAULT_HEADER, '')

    try:
      ValidateToken(token)
    except Error as err:
      handler.abort(
          httplib.FORBIDDEN,
          explanation='Error processing the XSRF token',
          detail=repr(err))
    else:
      return method(handler, *args, **kwargs)

  return RequireTokenWrapper
