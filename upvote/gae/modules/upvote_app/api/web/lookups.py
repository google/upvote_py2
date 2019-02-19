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

"""Handlers for looking up extra info on binaries."""

import httplib
import logging

import webapp2
from webapp2_extras import routes

from upvote.gae.datastore.models import base as base_models
from upvote.gae.datastore.models import package as package_models
from upvote.gae.datastore.models import santa as santa_models
from upvote.gae.lib.analysis import api as analysis_api
from upvote.gae.lib.analysis.virustotal import constants as vt_constants
from upvote.gae.modules.upvote_app.api.web import monitoring
from upvote.gae.utils import handler_utils


class Lookup(handler_utils.UserFacingHandler):
  """Handler for looking up binary info."""

  @property
  def RequestCounter(self):
    return monitoring.event_requests

  @handler_utils.RecordRequest
  def check_virus_total(self, blockable_id):
    blockable = base_models.Blockable.get_by_id(blockable_id)
    if not blockable:
      self.abort(httplib.NOT_FOUND, explanation='Blockable not found')

    if isinstance(blockable, package_models.SantaBundle):
      keys = package_models.SantaBundle.GetBundleBinaryKeys(blockable.key)
      all_results = {
          'response_code': vt_constants.RESPONSE_CODE.UNKNOWN,
          'positives': 0,
          'reports': {}}
      for key in keys:
        try:
          results = analysis_api.VirusTotalLookup(key.id())
        except analysis_api.FailedLookupError as e:  # pylint: disable=broad-except
          # NOTE: We suppress all errors here because an omitted entry will be
          # considered an error and prevent the response from being considered
          # fully analyzed.
          logging.warning(str(e))
        else:
          if 'scans' in results:
            del results['scans']
          all_results['positives'] += bool(results.get('positives'))
          all_results['reports'][key.id()] = results

      # If all binaries have reports, set response to ANALYZED.
      if (len(all_results['reports']) == len(keys) and
          all('total' in report for report in all_results['reports'].values())):
        all_results['response_code'] = vt_constants.RESPONSE_CODE.ANALYZED

      self.respond_json(all_results)
    else:
      try:
        results = analysis_api.VirusTotalLookup(blockable_id)
      except analysis_api.FailedLookupError as e:  # pylint: disable=broad-except
        logging.exception(str(e))
        self.abort(httplib.NOT_FOUND)
      else:
        self.respond_json(results)


# The Webapp2 routes defined for these handlers.
ROUTES = routes.PathPrefixRoute('/check', [
    webapp2.Route(
        r'/virustotal/<blockable_id>',
        handler=Lookup,
        handler_method='check_virus_total'),
])
