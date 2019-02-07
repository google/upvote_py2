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

"""Model definitions for Upvote users."""

import datetime
import logging
import random

from google.appengine.api import users
from google.appengine.ext import ndb

from upvote.gae import settings
from upvote.gae.bigquery import tables
from upvote.gae.datastore.models import mixin
from upvote.gae.utils import mail_utils
from upvote.gae.utils import template_utils
from upvote.gae.utils import user_utils
from upvote.shared import constants


_ROLLOUT_GROUP_COUNT = 1000
_UNASSIGNED_ROLLOUT_GROUP = -1


class Error(Exception):
  """Base error for models."""


class UnknownUserError(Error):
  """The current user cannot be accurately determined for some reason."""


class InvalidUserRoleError(Error):
  """The called function received an invalid user role."""


class NoRolesError(Error):
  """Raised if an User has (or will have) no assigned roles."""


def _ValidateRolloutGroup(unused_prop, value):
  if ((value < 0 or value >= _ROLLOUT_GROUP_COUNT) and
      value != _UNASSIGNED_ROLLOUT_GROUP):
    raise ValueError('Invalid rollout group: %d' % value)


class User(mixin.Base, ndb.Model):
  """Represents a user in Upvote for voting purposes.

  Tracks the reputation of a single user to determine how much weight their
  votes are worth. Endorsing malware reduces a user's reputation and as a
  result the value of their votes.

  key = user email

  Attributes:
    recorded_dt: datetime, time of insertion.
    vote_weight: int, the weight of their votes.
    roles: string, all roles for current user, i.e. TRUSTED_USER, SECURITY, etc.
    last_vote_dt: datetime, last time this user voted.
    rollout_group: int, a random integer in the range [0, _ROLLOUT_GROUP_COUNT)
        assigned at creation-time.
  """
  _PERMISSION_PROPERTIES = {
      constants.SYSTEM.BIT9: 'bit9_perms',
      constants.SYSTEM.SANTA: 'santa_perms',
  }

  recorded_dt = ndb.DateTimeProperty(auto_now_add=True)
  vote_weight = ndb.IntegerProperty(default=1)
  roles = ndb.StringProperty(repeated=True, choices=constants.USER_ROLE.SET_ALL)
  last_vote_dt = ndb.DateTimeProperty(default=None)
  rollout_group = ndb.IntegerProperty(
      required=True, validator=_ValidateRolloutGroup,
      default=_UNASSIGNED_ROLLOUT_GROUP)

  @classmethod
  @ndb.transactional
  def _InnerGetOrInsert(cls, email_addr):
    email_addr = email_addr.lower()
    user = cls.get_by_id(email_addr)
    if user is None:

      logging.info('Creating new user %s', email_addr)
      initial_roles = [constants.USER_ROLE.USER]
      user = cls(id=email_addr, roles=initial_roles)
      user.AssignRolloutGroup()
      user.put()

      tables.USER.InsertRow(
          email=email_addr,
          timestamp=datetime.datetime.utcnow(),
          action=constants.USER_ACTION.FIRST_SEEN,
          roles=initial_roles)
    return user

  @classmethod
  def GetOrInsert(cls, email_addr=None, appengine_user=None):
    """Creates a new User, or retrieves an existing one.

    NOTE: Use this anywhere you would otherwise do an __init__() and put(). We
    need to ensure that the roles Property gets initialized for new users, but
    can't specify a default value.

    Args:
      email_addr: Optional email address string to create the User from.
      appengine_user: Optional AppEngine User to create the User from.

    Returns:
      The User instance.

    Raises:
      UnknownUserError: The current user cannot be determined via either email
          address or AppEngine user.
    """
    # Ultimately, we need an email address. If one isn't specified, fall back
    # to the logged in AppEngine user.
    if email_addr is None:
      appengine_user = appengine_user or users.get_current_user()

      # If we can't fall back to an AppEngine user for some reason, bail.
      if appengine_user is None:
        raise UnknownUserError

      email_addr = appengine_user.email()

    # Do a simple get to see if an User entity already exists for this
    # user. Otherwise, incur a transaction in order to create a new one.
    return cls.GetById(email_addr) or cls._InnerGetOrInsert(email_addr)

  @classmethod
  def GetById(cls, email_addr):
    """Retrieves an existing User.

    NOTE: Use this anywhere you would otherwise do a get_by_id(). We
    need to ensure that the email address is properly tranlated to the internal
    form.

    Args:
      email_addr: The email address string associated with the desired
          User.

    Returns:
      The User instance or None.
    """
    return cls.get_by_id(email_addr.lower())

  @classmethod
  @ndb.transactional(xg=True)  # User and KeyValueCache
  def SetRoles(cls, email_addr, new_roles):

    user = User.GetOrInsert(email_addr)
    old_roles = set(user.roles)
    new_roles = set(new_roles)
    all_roles = constants.USER_ROLE.SET_ALL

    # Removing all roles would put this user into a bad state, so don't.
    if not new_roles:
      msg = 'Cannot remove remaining role(s) %s from user %s' % (
          sorted(list(old_roles)), user.nickname)
      logging.error(msg)
      raise NoRolesError(msg)

    # Verify that all the roles provided are valid.
    invalid_roles = new_roles - all_roles
    if invalid_roles:
      raise InvalidUserRoleError(', '.join(invalid_roles))

    # If no role changes are necessary, bail.
    if old_roles == new_roles:
      logging.info('No roles changes necessary for %s', user.nickname)
      return

    # Log the roles changes.
    roles_removed = old_roles - new_roles
    for role in roles_removed:
      logging.info('Removing the %s role from %s', role, user.nickname)
    roles_added = new_roles - old_roles
    for role in roles_added:
      logging.info('Adding the %s role to %s', role, user.nickname)

    # Recalculate the voting weight.
    voting_weights = settings.VOTING_WEIGHTS
    new_vote_weight = max(voting_weights[role] for role in new_roles)
    if user.vote_weight != new_vote_weight:
      logging.info(
          'Vote weight changing from %d to %d for %s', user.vote_weight,
          new_vote_weight, user.nickname)

    new_roles = sorted(list(new_roles))
    user.roles = new_roles
    user.vote_weight = new_vote_weight
    user.put()

    # Notify the user of the change.
    roles_added_str = ', '.join(sorted(roles_added))
    roles_removed_str = ', '.join(sorted(roles_removed))
    body = template_utils.RenderEmailTemplate(
        'user_role_change.html', roles_added=roles_added_str,
        roles_removed=roles_removed_str)
    subject = 'Your user roles have changed'
    mail_utils.Send(subject, body, to=[user.email], html=True)

    # Note the role change in BigQuery.
    tables.USER.InsertRow(
        email=user.email,
        timestamp=datetime.datetime.utcnow(),
        action=constants.USER_ACTION.ROLE_CHANGE,
        roles=new_roles)

  @classmethod
  @ndb.transactional(xg=True)  # User and KeyValueCache
  def UpdateRoles(cls, email_addr, add=None, remove=None):
    user = User.GetOrInsert(email_addr)
    new_roles = set(user.roles).union(add or set()).difference(remove or set())
    cls.SetRoles(email_addr, new_roles)

  def _pre_put_hook(self):
    # Ensure that the email address was properly converted to lowercase.
    assert self.key.id().lower() == self.key.id()

    self.roles = sorted(list(set(self.roles)))

  def _GetAllPermissions(self):
    permissions = set()
    for role in self.roles:
      role_permissions = getattr(constants.PERMISSIONS, 'SET_%s' % role, ())
      permissions = permissions.union(role_permissions)
    return permissions

  @property
  def permissions(self):
    if not hasattr(self, '_permissions'):
      self._permissions = self._GetAllPermissions()
    return self._permissions

  @property
  def email(self):
    return self.key.string_id()

  @property
  def nickname(self):
    return user_utils.EmailToUsername(self.key.string_id())

  @property
  def highest_role(self):
    """Returns the highest role for the user, by voting weight."""
    role_set = set(self.roles)
    for role, _ in sorted(
        settings.VOTING_WEIGHTS.iteritems(), key=lambda t: t[1], reverse=True):
      if role in role_set:
        return role

    # "This should never happen", but you know how that goes...
    raise NoRolesError

  @property
  def is_admin(self):
    has_admin_role = bool(set(self.roles) & constants.USER_ROLE.SET_ADMIN_ROLES)
    is_failsafe = self.email in settings.FAILSAFE_ADMINISTRATORS
    return has_admin_role or is_failsafe

  def HasRolloutGroup(self):
    """Indicates if this User has a rollout_group assigned."""
    return self.rollout_group != _UNASSIGNED_ROLLOUT_GROUP

  def AssignRolloutGroup(self):
    """Assigns a rollout_group value to this User.


    Returns:
      True if a rollout_group was assigned, False otherwise.
    """
    if not self.HasRolloutGroup():
      self.rollout_group = random.randrange(0, _ROLLOUT_GROUP_COUNT)
      return True
    return False

  def HasPermissionTo(self, task):
    """Verifies the User has permission to complete a task.

    Args:
      task: str, task being gated by permissions. One of constants.PERMISSIONS.*

    Returns:
      Boolean. True if user has the requested permission.
    """
    return self.is_admin or task in self.permissions
