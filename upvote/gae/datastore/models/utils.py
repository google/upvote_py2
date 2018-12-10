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

"""Datastore Model-related utility functions."""

from google.appengine.ext import ndb

from upvote.gae import settings
from upvote.gae.datastore.models import base as base_models
from upvote.gae.datastore.models import exemption as exemption_models
from upvote.gae.datastore.models import host as host_models
from upvote.gae.datastore.models import santa as santa_models
from upvote.gae.datastore.models import user as user_models
from upvote.gae.shared.common import user_map
from upvote.shared import constants


def GetBit9HostKeysForUser(user):
  """Returns the Keys of all Bit9Hosts associated with the given user.

  Args:
    user: The User in question.

  Returns:
    A list of Bit9Host Keys.
  """
  query = host_models.Bit9Host.query(
      host_models.Bit9Host.users == user.nickname)
  return query.fetch(keys_only=True)


def GetBit9HostIdsForUser(user):
  return [key.id() for key in GetBit9HostKeysForUser(user)]


def GetSantaHostKeysForUser(user):
  """Returns the Keys of all SantaHosts associated with the given user.

  Args:
    user: The User in question.

  Returns:
    A list of SantaHost Keys.
  """
  hosts_query = host_models.SantaHost.query(
      host_models.SantaHost.primary_user == user.nickname)
  hosts_future = hosts_query.fetch_async(keys_only=True)

  # If a user has been logged in to a Host when an Event was registered, they
  # are associated with that Host.
  events_query = santa_models.SantaEvent.query(
      ancestor=user.key,
      projection=[santa_models.SantaEvent.host_id],
      distinct=True)
  events_future = events_query.fetch_async()

  all_keys = set(hosts_future.get_result())
  for event in events_future.get_result():
    all_keys.add(ndb.Key(host_models.SantaHost, event.host_id))
  return list(all_keys)


def GetSantaHostIdsForUser(user):
  return [key.id() for key in GetSantaHostKeysForUser(user)]


def GetHostKeysForUser(user):
  return GetBit9HostKeysForUser(user) + GetSantaHostKeysForUser(user)


def GetHostIdsForUser(user):
  return GetBit9HostIdsForUser(user) + GetSantaHostIdsForUser(user)


def GetExemptionsForUser(email_addr, state=None):
  user = user_models.User.GetById(email_addr)
  exm_keys = [
      exemption_models.Exemption.CreateKey(host_id)
      for host_id in GetHostIdsForUser(user)]
  exms = [exm for exm in ndb.get_multi(exm_keys) if exm]
  if state:
    exms = [exm for exm in exms if exm.state == state]
  return exms


def GetEventKeysToInsert(event, logged_in_users, host_owners):
  """Returns the list of keys with which this Event should be inserted."""
  if settings.EVENT_CREATION == constants.EVENT_CREATION.EXECUTING_USER:
    if event.run_by_local_admin:
      usernames = logged_in_users
    else:
      usernames = [event.executing_user] if event.executing_user else []
  else:  # HOST_OWNERS
    usernames = host_owners

  emails = [user_map.UsernameToEmail(username) for username in usernames]

  keys = []
  for email in emails:
    key_pairs = [
        (user_models.User, email.lower()),
        (host_models.Host, event.host_id)]
    key_pairs += event.blockable_key.pairs()
    key_pairs += [(base_models.Event, '1')]
    keys.append(ndb.Key(pairs=key_pairs))
  return keys


def IsBit9HostAssociatedWithUser(host, user):
  return user.nickname in host.users


def IsSantaHostAssociatedWithUser(host, user):
  """Returns whether the given user is associated with this host."""

  if user.nickname == host.primary_user:
    return True

  # If a user has been logged in to this Host when an Event was registered,
  # they are associated with this Host.
  parent_key = ndb.Key(host_models.SantaHost, host.key.id(), parent=user.key)
  query = santa_models.SantaEvent.query(ancestor=parent_key)
  return query.get(keys_only=True) is not None


def IsHostAssociatedWithUser(host, user):
  """Returns whether the given host is associated with a given user.

  NOTE: What consitutes "associated with" is platform-dependent.

  Args:
    host: The Host entity to test.
    user: The User entity to test.

  Returns:
    bool, Whether the host is associated with the user.
  """
  if isinstance(host, host_models.Bit9Host):
    return IsBit9HostAssociatedWithUser(host, user)
  elif isinstance(host, host_models.SantaHost):
    return IsSantaHostAssociatedWithUser(host, user)
  else:
    raise ValueError('Unsupported Host class: %s' % host.__class__.__name__)


def GetUsersAssociatedWithSantaHost(host_id):

  event_query = base_models.Event.query(
      base_models.Event.host_id == host_id,
      projection=[base_models.Event.executing_user],
      distinct=True)

  return [
      e.executing_user for e in event_query.fetch()
      if e.executing_user != constants.LOCAL_ADMIN.MACOS]
