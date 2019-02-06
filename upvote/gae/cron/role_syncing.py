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

"""Cron job to sync Upvote roles with external user groups."""

import httplib
import logging

import webapp2
from webapp2_extras import routes

from google.appengine.ext import deferred
from google.appengine.ext import ndb

from upvote.gae import settings
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import host as host_models
from upvote.gae.datastore.models import user as user_models
from upvote.gae.utils import group_utils
from upvote.gae.utils import handler_utils
from upvote.gae.utils import iter_utils
from upvote.gae.utils import monitoring_utils
from upvote.gae.utils import user_utils
from upvote.monitoring import metrics
from upvote.shared import constants

# This number may need tweaking.
BATCH_SIZE = 1000

# Done for the sake of brevity.
_CLIENT_MODE = constants.CLIENT_MODE

_SYNCING_ERRORS = monitoring_utils.Counter(metrics.ROLES.SYNCING_ERRORS)


class SyncRoles(handler_utils.CronJobHandler):
  """Handler for syncing roles."""

  def get(self):  # pylint: disable=g-bad-name

    logging.info('Starting role sync...')
    group_role_assignments = settings.GROUP_ROLE_ASSIGNMENTS
    group_client = group_utils.GroupManager()

    # Iterate over the syncing dict, where each entry consists of a role key
    # which maps to a list of groups that should have that role.
    for role, group_names in sorted(group_role_assignments.iteritems()):

      logging.info('Syncing role %s to %s', role, group_names)
      ndb_roster = user_models.User.query(
          user_models.User.roles == role)

      # Make sure all of the groups actually exist first.
      skip_current_role = False
      for group in group_names:

        # If we're trying to sync a group that doesn't exist, make some noise.
        if not group_client.DoesGroupExist(group):
          logging.error(
              'Skipping sync of role %s, group %s does not exist', role,
              group)
          _SYNCING_ERRORS.Increment()
          self.response.set_status(httplib.NOT_FOUND)
          skip_current_role = True
          break

      # If we hit a nonexistent group, move on to the next role.
      if skip_current_role:
        continue

      # Gather all users in the set of groups associated with the current role.
      expected_roster = set()
      for group in group_names:
        expected_roster |= set(group_client.AllMembers(group))

      # If this is an admin role, ensure that the failsafe admins are included.
      if role in constants.USER_ROLE.SET_ADMIN_ROLES:
        expected_roster.update(settings.FAILSAFE_ADMINISTRATORS)

      logging.info(
          'There are %d user(s) in total who should have the %s role',
          len(expected_roster), role)

      additions = 0
      removals = 0

      # For each user that already has the current role, make sure that
      # they're supposed to, and remove the role from them if they aren't.
      for ndb_user in ndb_roster:
        if ndb_user.email not in expected_roster:
          try:
            user_models.User.UpdateRoles(ndb_user.email, remove=[role])
            removals += 1
          except user_models.NoRolesError:
            logging.error(
                'Error encountered while removing role(s) from %s',
                ndb_user.email)
            _SYNCING_ERRORS.Increment()
        else:
          expected_roster.remove(ndb_user.email)

      # At this point, the remaining users retrieved from the group client
      # should all be users which don't have the current role, but should.
      for user in expected_roster:
        user_models.User.UpdateRoles(user, add=[role])
        additions += 1

      logging.info(
          'Sync of the %s role resulted in %d addition(s) and %d removal(s)',
          role, additions, removals)


class ClientModeChangeHandler(handler_utils.CronJobHandler):
  """Generic parent class for setting client mode for hosts."""

  def _ChangeModeForGroup(self, mode, group, honor_lock=True):
    """Loads all users in the group and sets the client_mode for their hosts.

    This will make sure that hosts are in the right mode if they are members of
    a group, but will not change mode for non-members. Users can be left out of
    groups to be manaully managed.

    Args:
      mode: The new client_mode to set.
      group: The group of users whose hosts should have a mode change.
      honor_lock: bool, whether the client_mode will be honored.
    """
    logging.info('Changing mode to %s for %s', mode, group)

    group_client = group_utils.GroupManager()
    roster = group_client.AllMembers(group)
    logging.info('Fetched %d user(s) from group %s', len(roster), group)

    # Generate the NDB Keys for all users in the roster.
    user_keys = [
        ndb.Key(user_models.User, email) for email in roster if email]

    # ndb.OR falls over if it gets an empty iterable...
    if not user_keys:
      return

    for user_key_group in iter_utils.Grouper(user_keys, BATCH_SIZE):
      user_key_group = filter(None, user_key_group)
      deferred.defer(
          _ChangeModeForHosts, mode, user_key_group, honor_lock,
          _queue=constants.TASK_QUEUE.DEFAULT)


def _ChangeModeForHosts(mode, user_keys, honor_lock=True):
  """Performs a client mode change for the specified users' hosts.

  Args:
    mode: The new client_mode to set.
    user_keys: The users whose host modes are to be changed.
    honor_lock: bool, whether the client_mode_lock property will be honored.
  """
  predicates = [
      host_models.SantaHost.primary_user == user_utils.EmailToUsername(key.id())
      for key in user_keys]
  query = host_models.SantaHost.query(ndb.OR(*predicates))
  hosts = query.fetch()
  updated_hosts = []

  for host in hosts:

    # If lock is honored, skip locked users.
    if honor_lock and host.client_mode_lock:
      continue

    # Ignore non-changes also.
    if host.client_mode == mode:
      continue

    # Proceed with the mode change.
    host.client_mode = mode
    host.client_mode_lock = False
    updated_hosts.append(host)

  ndb.put_multi(updated_hosts)
  logging.info(
      'Client mode changed to %s for %d host(s)', mode, len(updated_hosts))


class LockItDown(ClientModeChangeHandler):
  """Puts hosts into lockdown mode."""

  def get(self):  # pylint: disable=g-bad-name
    self._ChangeModeForGroup(
        _CLIENT_MODE.LOCKDOWN, settings.LOCKDOWN_GROUP, honor_lock=False)


class MonitorIt(ClientModeChangeHandler):
  """Puts hosts into monitor mode."""

  def get(self):  # pylint: disable=g-bad-name
    self._ChangeModeForGroup(
        _CLIENT_MODE.MONITOR, settings.MONITOR_GROUP, honor_lock=False)


class LockSpider(handler_utils.CronJobHandler):
  """Crawls through host entities and locks them down if they are not locked."""

  def get(self):  # pylint: disable=g-bad-name
    # pylint: disable=g-explicit-bool-comparison, singleton-comparison
    query = host_models.SantaHost.query(
        host_models.SantaHost.client_mode == _CLIENT_MODE.MONITOR,
        host_models.SantaHost.client_mode_lock == False)
    datastore_utils.QueuedPaginatedBatchApply(
        query, _SpiderBite, page_size=BATCH_SIZE,
        queue=constants.TASK_QUEUE.QUERY, keys_only=True)


def _SpiderBite(host_keys):
  hosts = ndb.get_multi(host_keys)
  for host in hosts:
    host.client_mode = _CLIENT_MODE.LOCKDOWN

  ndb.put_multi(hosts)
  logging.info(
      'Client mode changed to LOCKDOWN for %d host(s)', len(hosts))


ROUTES = routes.PathPrefixRoute('/roles', [
    webapp2.Route('/sync', handler=SyncRoles),
    webapp2.Route('/lock-it-down', handler=LockItDown),
    webapp2.Route('/monitor-it', handler=MonitorIt),
    webapp2.Route('/lock-spider', handler=LockSpider),
])
