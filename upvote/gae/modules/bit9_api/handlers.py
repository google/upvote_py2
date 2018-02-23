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

"""Handlers for interacting with the bit9_arbiter RPC service."""

import datetime
import httplib
import logging

from google.appengine.ext import ndb

from common import memcache_decorator

from upvote.gae.datastore.models import base as base_db
from upvote.gae.datastore.models import bit9 as bit9_db
from upvote.gae.modules.bit9_api import change_set
from upvote.gae.modules.bit9_api import constants as bit9_constants
from upvote.gae.modules.bit9_api import rest_utils
from upvote.gae.modules.bit9_api import utils
from upvote.gae.modules.bit9_api.api import api
from upvote.gae.shared.common import handlers
from upvote.gae.shared.common import settings
from upvote.shared import constants

_HOST_HEALTH_PROPS = bit9_constants.UpvoteHostHealthProperties
_HOST_HEALTH_TIMEOUT = datetime.timedelta(minutes=5).total_seconds()
_ASSOCIATED_HOSTS_TIMEOUT = datetime.timedelta(minutes=15).total_seconds()


class CommitBlockableChangeSet(handlers.UpvoteRequestHandler):
  """Triggers a deferred commit attempt for a given Blockable's change sets."""

  def get(self, blockable_id):
    blockable = base_db.Blockable.get_by_id(blockable_id)
    if blockable is None:
      self.abort(httplib.NOT_FOUND, explanation='Blockable does not exist')

    platform = blockable.GetPlatformName()
    if platform != constants.PLATFORM.WINDOWS:
      self.abort(
          httplib.BAD_REQUEST,
          explanation='Invalid Blockable platform: %s' % (platform))

    change_set.DeferCommitBlockableChangeSet(blockable.key)


@memcache_decorator.Cached(expire_time=_HOST_HEALTH_TIMEOUT)
def _GetHostHealthInformation(host_id):
  host = api.Computer.get(host_id, utils.CONTEXT)
  return {
      _HOST_HEALTH_PROPS.NAME:
          rest_utils.StripDownLevelDomain(host.name),
      _HOST_HEALTH_PROPS.CONNECTED: host.connected,
      _HOST_HEALTH_PROPS.LAST_REGISTER_DATE:
          host.last_register_date.strftime(
              bit9_constants.DATETIME_CONVERSION_STRING),
      _HOST_HEALTH_PROPS.AGENT_VERSION: host.agent_version,
      _HOST_HEALTH_PROPS.HAS_HEALTH_CHECK_ERRORS:
          host.has_health_check_errors,
      _HOST_HEALTH_PROPS.POLICY_NAME: host.policy_name,
      _HOST_HEALTH_PROPS.AGENT_CACHE_SIZE: host.agent_cache_size,
      _HOST_HEALTH_PROPS.IS_INITIALIZING: (
          host.initializing or host.init_percent != 100),
  }


class GetHostHealthInformation(handlers.UpvoteRequestHandler):
  """Gets information about the health of a host with a given host id."""

  def get(self):
    host_id = self.request.get('host_id')
    if not host_id:
      logging.warning(
          'Host health information request does not contain a host_id.')
      self.abort(httplib.BAD_REQUEST)

    # NOTE: Pass host_id through str because it's a BytesIO instance. The
    # memcache decorator needs picklable input and, since BytesIO is file-like,
    # it cannot be pickled.
    response = _GetHostHealthInformation(str(host_id))

    self.respond_json(response)


@memcache_decorator.Cached(expire_time=_ASSOCIATED_HOSTS_TIMEOUT)
def _GetAssociatedHosts(username):
  """Gets all hosts associated with the provided user."""
  queries = (r'*{0}\\{lower}',                    # Normal user at list end.
             r'*{0}\\{lower},*',)                 # Normal user in list middle.
  host_user_query = '|'.join(queries).format(
      settings.AD_DOMAIN,
      lower=username.lower(),
  )
  hosts = (api.Computer.query()
           .filter(api.Computer.users == host_user_query)
           .execute(utils.CONTEXT))

  return [
      host
      for host in hosts
      if username in rest_utils.ExtractHostUsers(host.users)]


class AssociatedHosts(handlers.UpvoteRequestHandler):
  """Provides an interface for the hosts associated with a given user."""

  def get(self, user_id):
    user = base_db.User.GetById(user_id)
    if user is None:
      logging.warning('Unknown user ID: %s', user_id)
      self.abort(httplib.NOT_FOUND)

    bit9_hosts = _GetAssociatedHosts(user.nickname)
    ids = [str(host.id) for host in bit9_hosts]

    # Get Host datastore entities corresponding to the IDs retrieved.
    gae_hosts = ndb.get_multi(ndb.Key(bit9_db.Bit9Host, id_) for id_ in ids)
    hosts_to_put = []
    for gae_host, bit9_host in zip(gae_hosts, bit9_hosts):
      policy_key = (
          ndb.Key(bit9_db.Bit9Policy, str(bit9_host.policy_id))
          if bit9_host.policy_id is not None
          else None)
      changed = False
      if gae_host is None:
        # If the host doesn't exist, create it.
        hostname = utils.ExpandHostname(
            rest_utils.StripDownLevelDomain(bit9_host.name))
        gae_host = bit9_db.Bit9Host(
            id=str(bit9_host.id),
            hostname=hostname,
            last_event_dt=None,
            policy_key=policy_key,
            users=rest_utils.ExtractHostUsers(bit9_host.users))
        changed = True
      else:
        # If the host does exist, update any changed fields.
        if gae_host.policy_key != policy_key:
          gae_host.policy_key = policy_key
          changed = True
        if set(gae_host.users) != set(bit9_host.users):
          gae_host.users = bit9_host.users
          changed = True

      if changed:
        hosts_to_put.append(gae_host)

    if hosts_to_put:
      logging.info('Updating %s Bit9Hosts...', len(hosts_to_put))
      ndb.put_multi(hosts_to_put)

    self.respond_json(ids)
