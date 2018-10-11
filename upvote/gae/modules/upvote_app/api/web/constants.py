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

"""Handlers related to Constants."""
import httplib
import logging

import webapp2

from upvote.gae.modules.upvote_app.api import monitoring
from upvote.gae.modules.upvote_app.api.web import base
from upvote.gae.shared.common import handlers
from upvote.shared import constants


class Constant(base.BaseHandler):
  """Get the value for a constant."""

  @property
  def RequestCounter(self):
    return monitoring.constant_requests

  @base.RequireCapability(constants.PERMISSIONS.VIEW_CONSTANTS)
  @handlers.RecordRequest
  def get(self, constant):  # pylint: disable=g-bad-name
    """Get handler for single setting.

    NOTE: The `constant` URI parameter will be properly parsed if it contains
    special URI characters (e.g. underscores).

    Args:
      constant: str. The name of the constant being requested.
    """
    logging.info('Constants handler get method called.')
    if constant.lower() == 'userrole':
      constant_value = {'UserRole': constants.USER_ROLE.SET_ALL}
      self.respond_json(constant_value)
    else:
      logging.info('Unknown constant requested: %s', constant)
      self.abort(httplib.NOT_FOUND, explanation='Unknown constant requested')


# The Webapp2 routes defined for these handlers.
ROUTES = webapp2.Route('/constants/<constant>', handler=Constant)
