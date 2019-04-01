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

"""Handlers related to Users."""
import httplib
import logging

import webapp2
from webapp2_extras import routes

from upvote.gae.datastore.models import user as user_models
from upvote.gae.modules.upvote_app.api.web import monitoring
from upvote.gae.utils import handler_utils
from upvote.shared import constants


class UserQueryHandler(handler_utils.UserFacingQueryHandler):
  """Handler for querying users."""

  MODEL_CLASS = user_models.User
  HAS_INTEGRAL_ID_TYPE = False

  @property
  def RequestCounter(self):
    return monitoring.user_requests

  @handler_utils.RequirePermission(constants.PERMISSIONS.VIEW_OTHER_USERS)
  @handler_utils.RecordRequest
  def get(self):
    self._Query()


class UserHandler(handler_utils.UserFacingHandler):
  """Handler for interacting with individual users."""

  def get(self, user_id=None):  # pylint: disable=g-bad-name
    logging.info('UserHandler GET method called with ID: %s', user_id)
    if not user_id or self.user.email == user_id:
      user = self.user
    else:
      user = self._get_another_user(user_id)
    if user:
      user_info = user.to_dict()
      user_info.update({
          'name': user.nickname,
          'permissions': user.permissions,
          'is_admin': user.is_admin,
      })
      self.respond_json(user_info)
    else:
      self.abort(httplib.NOT_FOUND, explanation='User not found')

  @handler_utils.RequirePermission(constants.PERMISSIONS.VIEW_OTHER_USERS)
  def _get_another_user(self, user_id):
    return user_models.User.GetById(user_id)


# The Webapp2 routes defined for these handlers.
ROUTES = routes.PathPrefixRoute('/users', [
    webapp2.Route(
        '/query',
        handler=UserQueryHandler),
    webapp2.Route(
        '/<user_id>',
        handler=UserHandler),
    webapp2.Route(
        '/',
        handler=UserHandler),
    webapp2.Route(
        '',
        handler=UserHandler),
])
