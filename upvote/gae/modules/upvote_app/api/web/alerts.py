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

"""Request handlers for Alert entities."""

import datetime
import httplib
import logging

import webapp2
from webapp2_extras import routes

from google.appengine.api import memcache
from google.appengine.ext import ndb

from upvote.gae.datastore.models import alert as alert_models
from upvote.gae.utils import handler_utils
from upvote.gae.utils import xsrf_utils
from upvote.shared import constants


_DEFAULT_MEMCACHE_TIMEOUT = datetime.timedelta(days=7).total_seconds()
_DATETIME_FORMAT_STRING = '%Y-%m-%dT%H:%M:%SZ'


# Done for the sake of brevity.
SITE_ALERT_SCOPE = constants.SITE_ALERT_SCOPE
SITE_ALERT_PLATFORM = constants.SITE_ALERT_PLATFORM


def _CreateMemcacheKey(scope, platform):
  pieces = ['alert', scope, platform]
  return '_'.join(p.lower() for p in pieces if p)


class AlertHandler(handler_utils.UserFacingHandler):
  """Handler for interacting with user-facing alert messages."""

  def _ValidateRouteParams(self, scope, platform):

    if not SITE_ALERT_SCOPE.Contains(scope, ignore_case=True):
      self.abort(httplib.BAD_REQUEST, 'Invalid scope: %s' % scope)

    if not SITE_ALERT_PLATFORM.Contains(platform, ignore_case=True):
      self.abort(httplib.BAD_REQUEST, 'Invalid platform: %s' % platform)

    scope = SITE_ALERT_SCOPE.Get(scope)
    platform = SITE_ALERT_PLATFORM.Get(platform)

    return scope, platform

  def get(self, scope, platform):

    scope, platform = self._ValidateRouteParams(scope, platform)

    # Check Memcache first.
    memcache_key = _CreateMemcacheKey(scope, platform)
    alert_dict = memcache.get(memcache_key)
    if alert_dict:
      self.respond_json(alert_dict)

    # Fall back and check Datastore.
    else:

      logging.info('No Alert found in Memcache at %s', memcache_key)

      # Grab all Alerts for this combination of platform and scope, which have
      # a start_date in the past.
      now = datetime.datetime.utcnow()
      # pylint: disable=g-explicit-bool-comparison, singleton-comparison
      all_alerts = alert_models.Alert.query(
          ndb.OR(
              alert_models.Alert.scope == scope,
              alert_models.Alert.scope == SITE_ALERT_SCOPE.EVERYWHERE),
          ndb.OR(
              alert_models.Alert.platform == platform,
              alert_models.Alert.platform == SITE_ALERT_PLATFORM.ALL),
          alert_models.Alert.start_date <= now).fetch()
      # pylint: enable=g-explicit-bool-comparison, singleton-comparison

      active_alerts = []
      expired_alerts = []

      # Any Alerts which also have an end_date in the past can safely be
      # deleted. This will have the effect of automatically keeping Alert
      # entities pruned down to only those which are active or upcoming.
      for alert in all_alerts:
        if alert.end_date and alert.end_date < now:
          expired_alerts.append(alert)
        else:
          active_alerts.append(alert)
      logging.info('Found %d active Alert(s)', len(active_alerts))
      logging.info('Deleting %d expired Alert(s)', len(expired_alerts))
      ndb.delete_multi(a.key for a in expired_alerts)

      # It's unlikely, but possible, that there could be multiple overlapping
      # alerts active at a given time (e.g. a long-running degradation could be
      # interrupted by a short-term outage). So sort by most recent start date.
      active_alerts = sorted(
          active_alerts, key=lambda a: a.start_date, reverse=True)

      # If the last active Alert just expired, throw an empty placeholder dict
      # into Memcache. Otherwise, opt for the Alert with the most recent start
      # date.
      alert_dict = active_alerts[0].to_dict() if active_alerts else {}

      # The Memcache entry should expire when the Alert does, or at the default
      # time if no expiration is specified.
      alert_end_date = alert_dict.get('end_date')
      if alert_end_date:
        memcache_timeout = (alert_end_date - now).total_seconds()
      else:
        memcache_timeout = _DEFAULT_MEMCACHE_TIMEOUT

      # Keep the Memcache key set regardless of whether there's actually an
      # Alert, in order to cut down on needless NDB queries. We avoid false
      # negatives by purging Memcache any time administrative changes are made
      # via the POST handler below.
      memcache.set(memcache_key, alert_dict, time=memcache_timeout)

      self.respond_json(alert_dict)

  def _ParseRequestDate(self, request_arg):
    date_str = self.request.get(request_arg).strip()
    return (
        datetime.datetime.strptime(date_str, _DATETIME_FORMAT_STRING)
        if date_str else None)

  @xsrf_utils.RequireToken
  @handler_utils.RequirePermission(constants.PERMISSIONS.EDIT_ALERTS)
  def post(self, scope, platform):

    scope, platform = self._ValidateRouteParams(scope, platform)

    # Verify that the alert payload has the minimum requirements before going
    # any further.
    for request_arg in ('message', 'start_date', 'severity'):
      if not self.request.get(request_arg).strip():
        self.abort(
            httplib.BAD_REQUEST, 'Missing request argument: %s' % request_arg)

    alert_models.Alert.Insert(
        message=self.request.get('message'),
        details=self.request.get('details'),
        start_date=self._ParseRequestDate('start_date'),
        end_date=self._ParseRequestDate('end_date'),
        platform=platform,
        scope=scope,
        severity=self.request.get('severity'))

    # Expire the memcache key in case the newly-created Alert which should take
    # priority over a current one. We don't need to reset the key, the next
    # relevant GET request should take care of it automatically.
    memcache.delete(_CreateMemcacheKey(scope, platform))


# The Webapp2 routes defined for these handlers.
ROUTES = routes.PathPrefixRoute('/alerts', [
    webapp2.Route(
        '/<scope>/<platform>',
        handler=AlertHandler),
])
