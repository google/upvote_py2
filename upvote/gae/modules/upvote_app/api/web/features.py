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

"""Request handlers for restricting access to new features."""

import logging

import six.moves.http_client
import webapp2
from webapp2_extras import routes

from google.appengine.api import memcache
from upvote.gae.utils import group_utils
from upvote.gae.utils import handler_utils
from upvote.gae.utils import user_utils


# A mapping of feature names to lists of group names, whose members are allowed
# to utilize said feature.
_SUPPORTED_FEATURES = {
    # Transitive whitelisting support for Santa clients.
    'transitive_whitelisting': [],
}


class FeatureHandler(handler_utils.UserFacingHandler):
  """Handler for gating access to new features based on group membership."""

  def get(self, feature):

    # If requesting an unknown feature, fail closed.
    if feature not in _SUPPORTED_FEATURES:
      logging.error('Unsupported feature: %s', feature)
      self.abort(six.moves.http_client.FORBIDDEN)

    # See if memcache already has an entry for this feature.
    memcache_key = 'feature_%s' % feature
    csv_string = memcache.get(memcache_key)

    # If it's already in memcache, construct a set of approved usernames.
    if csv_string:
      approved_users = set(csv_string.split(','))

    # Otherwise there was a cache miss, so retrieve the list of all approved
    # users for this feature.
    else:

      try:

        approved_users = set()
        group_manager = group_utils.GroupManager()

        for group in _SUPPORTED_FEATURES[feature]:

          # If a group isn't found, fail closed.
          if not group_manager.DoesGroupExist(group):
            logging.error('Unknown group: %s', group)
            self.abort(six.moves.http_client.FORBIDDEN)

          approved_users |= set(
              user_utils.EmailToUsername(member)
              for member in group_manager.AllMembers(group))

        # Build a CSV string and stuff it in memcache for future use.
        csv_string = ','.join(sorted(list(approved_users)))
        memcache.set(memcache_key, csv_string)

      # If anything fails while interacting with the GroupManager, just fail
      # closed. Odds are the user doesn't have access to this feature anyway,
      # and should be able to go about their business without seeing an error
      # message.
      except Exception:  # pylint: disable=broad-except
        logging.exception('Unexpected error while retrieving group members')
        self.abort(six.moves.http_client.FORBIDDEN)

    approved = self.user.nickname in approved_users
    self.response.status = six.moves.http_client.OK if approved else six.moves.http_client.FORBIDDEN


# The Webapp2 routes defined for these handlers.
ROUTES = routes.PathPrefixRoute('/features', [
    webapp2.Route(
        '/<feature>',
        handler=FeatureHandler),
])
