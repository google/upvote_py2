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

"""Handlers related to Big Red Button."""
import httplib
import logging

import webapp2

from upvote.gae.modules.upvote_app.api.handlers import base
from upvote.gae.shared.common import big_red
from upvote.gae.shared.common import xsrf_utils
from upvote.shared import constants


class Emergency(base.BaseHandler):
  """Handlers related to emergency controls."""

  @base.RequireCapability(constants.PERMISSIONS.CHANGE_SETTINGS)
  def get(self):  # pylint: disable=g-bad-name
    """Get handler for emergency controls."""
    logging.debug('Emergency handler get method called.')
    big_red_button = big_red.BigRedButton()
    self.respond_json(big_red_button.get_button_status())

  @base.RequireCapability(constants.PERMISSIONS.CHANGE_SETTINGS)
  @xsrf_utils.RequireToken
  def post(self):
    """Post handler for emergency controls."""
    logging.debug('Emergency handler post method called.')
    big_red_button = big_red.BigRedButton()

    # The handler expects only one emergency value each time it's called.
    # The individual switch being thrown will either be 'true' or 'false'.
    if self.request.get('bigRedButton') == 'false':
      big_red_button.turn_everything_off()
    elif self.request.get('bigRedButton') == 'true':
      big_red_button.turn_on_big_red_button()
    elif self.request.get('bigRedButtonStop1') == 'true':
      big_red_button.turn_on_stop1()
    elif self.request.get('bigRedButtonStop2') == 'true':
      big_red_button.turn_on_stop2()
    elif self.request.get('bigRedButtonGo1') == 'true':
      big_red_button.turn_on_go1()
    elif self.request.get('bigRedButtonGo2') == 'true':
      big_red_button.turn_on_go2()
    else:
      self.abort(
          httplib.BAD_REQUEST, explanation='Improper switch or value set.')

    self.respond_json(big_red_button.get_button_status())


# The Webapp2 routes defined for these handlers.
ROUTES = webapp2.Route('/emergency', handler=Emergency)
