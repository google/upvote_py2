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

"""A module for the index handler."""

import httplib
import logging
import webapp2

from google.appengine.api import users
from upvote.gae.utils import handler_utils
from upvote.gae.utils import template_utils
from upvote.shared import constants


class IndexHandler(handler_utils.UserFacingHandler):
  """Base class for all index handlers."""

  def _Get(self):

    # Enable debugging if requested.
    try:
      debug = bool(int(self.request.get('debug', '0')))
    except ValueError:
      debug = False
    logging.info('Debugging is %s', 'enabled' if debug else 'disabled')

    # Write the jinja2 template rendering to the handler's repsonse.
    response_string = template_utils.RenderWebTemplate(
        self.TEMPLATE_NAME, debug=debug, username=users.get_current_user())
    self.response.set_status(httplib.OK)
    self.response.write(response_string)


class AdminIndexHandler(IndexHandler):

  TEMPLATE_NAME = 'admin-index.html'

  @handler_utils.RequireCapability(constants.PERMISSIONS.VIEW_ADMIN_CONSOLE)
  def get(self, *args, **kwargs):
    return self._Get()


class UserIndexHandler(IndexHandler):

  TEMPLATE_NAME = 'user-index.html'

  def get(self, *args, **kwargs):
    return self._Get()


ADMIN_ROUTE = webapp2.Route(
    r'/admin<:/?><:.*>', handler=AdminIndexHandler)

USER_ROUTE = webapp2.Route(
    r'/<:/?><:.*>', handler=UserIndexHandler)
