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

"""Handlers related to Settings."""

import httplib
import logging

from upvote.gae.modules.upvote_app.api import monitoring
from upvote.gae.modules.upvote_app.api.handlers import base
from upvote.gae.shared.common import handlers
from upvote.gae.shared.common import settings
from upvote.gae.shared.common import xsrf_utils
from upvote.gae.shared.models import bit9
from upvote.gae.shared.models import virustotal
from upvote.shared import constants
from upvote.shared import utils


class Settings(base.BaseHandler):
  """Get or set the value of a setting."""

  @property
  def RequestCounter(self):
    return monitoring.setting_requests

  @handlers.RecordRequest
  def get(self, setting):  # pylint: disable=g-bad-name
    """Get handler for settings."""
    logging.debug('Setting requested: %s', setting)
    try:
      formatted_setting = utils.CamelToSnakeCase(setting)
      value = getattr(settings, formatted_setting.upper())
    except AttributeError as e:
      logging.debug('Unable to retrieve setting.')
      self.abort(httplib.NOT_FOUND, explanation=str(e))
    else:
      self.respond_json(value)


class ApiKeys(base.BaseHandler):
  """Set/update the value of an API key."""

  @xsrf_utils.RequireToken
  @base.RequireCapability(constants.PERMISSIONS.CHANGE_SETTINGS)
  def post(self, key_name):  # pylint: disable=g-bad-name
    """Post handler for a single API key."""

    value = self.request.get('value', None)
    if value is None:
      self.abort(httplib.BAD_REQUEST, explanation='No value provided')

    if key_name == 'virustotal':
      virustotal.VirusTotalApiAuth.SetInstance(api_key=value)
    elif key_name == 'bit9':
      bit9.Bit9ApiAuth.SetInstance(api_key=value)
    else:
      self.abort(httplib.BAD_REQUEST, explanation='Invalid key name')
