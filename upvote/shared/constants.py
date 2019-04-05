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

"""Constants for Upvote."""

import string

_INVALID_NAME_CHARS = string.punctuation + string.whitespace
_VALUE_TO_NAME_TABLE = string.maketrans(
    _INVALID_NAME_CHARS, '_' * len(_INVALID_NAME_CHARS))


class Error(Exception):
  """Base Exception class."""


class InvalidNameError(Error):
  """Raised when referencing an invalid Namespace name."""


class Namespace(object):
  """Creates a collection of constants, each with a corresponding value."""

  def __init__(
      self, tuples=None, names=None, value_from_name=None, values=None,
      prefix='', suffix=''):
    """Constructor.

    Args:
      tuples: List of (constant_name, constant_value) tuples. Takes precedence
          over the 'names' and 'values' kwarg.
      names: List of constant names. Takes precedence over the 'values' kwarg.
      value_from_name: Optional function for creating a constant value from a
          constant name.
      values: List of constant values.
      prefix: Optional prefix to add to all values. Results in all values being
          converted to strings.
      suffix: Optional suffix to add to all values. Results in all values being
          converted to strings.

    Raises:
      ValueError: if constructed without at least one of the 'tuples', 'names',
          or 'values' kwargs.
    """
    if tuples:
      gen = (t for t in tuples)
    elif names:
      identity = lambda x: x
      value_from_name = value_from_name or identity
      gen = ((n, value_from_name(n)) for n in names)
    elif values:
      gen = ((v.translate(_VALUE_TO_NAME_TABLE), v) for v in values)
    else:
      raise ValueError('Must provide one of tuples, names, or values')

    # Ensure every name is all-caps.
    gen = ((n.upper(), v) for n, v in gen)

    # Attach prefixes and/or suffixes to the values if needed.
    if prefix or suffix:
      gen = ((n, '%s%s%s' % (prefix, v, suffix)) for n, v in gen)

    temp_name_set = set()
    temp_value_set = set()

    # Pull everything through the pipeline and create some constants.
    for name, value in gen:
      setattr(self, name, value)
      temp_name_set.add(name)
      temp_value_set.add(value)

    self._names = frozenset(temp_name_set)
    self._values = frozenset(temp_value_set)

    self.DefineSet('ALL', self._names)

  def DefineSet(self, set_name, constant_names):
    """Defines a named set of constants for this namespace.

    Args:
      set_name: The name of the set. Will be capitalized and prepended with
          'SET_'.
      constant_names: Iterable of constants whose values will be added to the
          set. Should all be strings, and should all be members of self._names.

    Raises:
      ValueError: Invalid constants were provided.
    """
    constant_names = set(constant_names)

    invalid_constants = constant_names - self._names
    if invalid_constants:
      raise ValueError('Invalid constant(s): ' + ', '.join(invalid_constants))

    constant_values = frozenset(getattr(self, name) for name in constant_names)
    setattr(self, 'SET_' + set_name.upper(), constant_values)

  def DefineMap(self, map_name, map_value):
    setattr(self, 'MAP_' + map_name.upper(), map_value)

  def Contains(self, value, ignore_case=False):
    values = self._values
    if isinstance(value, str) and ignore_case:
      value = value.lower()
      values = {v.lower() if isinstance(v, str) else v for v in self._values}
    return value in values

  def Get(self, name):

    name = name.upper()
    if name not in self._names:
      raise InvalidNameError(name)

    return getattr(self, name)


class UppercaseNamespace(Namespace):
  """Namespace where all values are uppercase strings."""

  def __init__(self, names, prefix=None, suffix=None):
    super(UppercaseNamespace, self).__init__(
        names=names, value_from_name=str.upper, prefix=prefix, suffix=suffix)


class LowercaseNamespace(Namespace):
  """Namespace where all values are lowercase strings."""

  def __init__(self, names, prefix=None, suffix=None):
    super(LowercaseNamespace, self).__init__(
        names=names, value_from_name=str.lower, prefix=prefix, suffix=suffix)



PLATFORM = Namespace(tuples=[
    ('MACOS', 'macOS'),
    ('WINDOWS', 'Windows')])


ANALYSIS_REASON = UppercaseNamespace(['NEW_BLOCKABLE', 'UPVOTE', 'DOWNVOTE'])


VALIDATION_MODE = UppercaseNamespace(['FAIL_CLOSED', 'FAIL_OPEN', 'NONE'])
SYSTEM = UppercaseNamespace(['bit9', 'santa'])


BLOCKABLE_TYPE = UppercaseNamespace(['santa_binary', 'santa_certificate'])


PERMISSIONS = UppercaseNamespace([
    'ADD_OVERRIDE', 'CHANGE_SETTINGS', 'EDIT_ALERTS', 'EDIT_HOSTS',
    'FLAG', 'INSERT_BLOCKABLES', 'MANAGE_EXEMPTIONS', 'MARK_INSTALLER',
    'MARK_MALWARE', 'REQUEST_EXEMPTION', 'RESET_BLOCKABLE_STATE',
    'RUN_BATCH_JOB', 'UNFLAG', 'VIEW_CONSTANTS', 'VIEW_ADMIN_CONSOLE',
    'VIEW_HOST_IP', 'VIEW_OTHER_BLOCKABLES', 'VIEW_OTHER_EVENTS',
    'VIEW_OTHER_HOSTS', 'VIEW_OTHER_USERS', 'VIEW_RULES', 'VIEW_VOTES', 'VOTE'
])

PERMISSIONS.DefineSet('UNTRUSTED_USER', [PERMISSIONS.FLAG])
PERMISSIONS.DefineSet('USER', [
    PERMISSIONS.FLAG, PERMISSIONS.REQUEST_EXEMPTION, PERMISSIONS.VOTE])

PERMISSIONS.DefineSet('TRUSTED_USER', PERMISSIONS.SET_USER.union([
    PERMISSIONS.MARK_INSTALLER, PERMISSIONS.MARK_MALWARE, PERMISSIONS.UNFLAG,
    PERMISSIONS.VIEW_CONSTANTS, PERMISSIONS.VIEW_ADMIN_CONSOLE,
    PERMISSIONS.VIEW_HOST_IP, PERMISSIONS.VIEW_OTHER_BLOCKABLES,
    PERMISSIONS.VIEW_OTHER_EVENTS, PERMISSIONS.VIEW_OTHER_HOSTS,
    PERMISSIONS.VIEW_OTHER_USERS, PERMISSIONS.VIEW_VOTES]))

PERMISSIONS.DefineSet('SUPERUSER', PERMISSIONS.SET_TRUSTED_USER.union([
    PERMISSIONS.RESET_BLOCKABLE_STATE, PERMISSIONS.EDIT_HOSTS]))

PERMISSIONS.DefineSet('SECURITY', PERMISSIONS.SET_SUPERUSER.union([
    PERMISSIONS.INSERT_BLOCKABLES, PERMISSIONS.VIEW_RULES]))

PERMISSIONS.DefineSet('ADMINISTRATOR', PERMISSIONS.SET_SECURITY.union([
    PERMISSIONS.ADD_OVERRIDE, PERMISSIONS.CHANGE_SETTINGS,
    PERMISSIONS.EDIT_ALERTS, PERMISSIONS.RUN_BATCH_JOB,
    PERMISSIONS.MANAGE_EXEMPTIONS]))


ID_TYPE = UppercaseNamespace(['SHA1', 'SHA256', 'FUZZY_SHA256', 'SANTA_BUNDLE'])

EVENT_TYPE = UppercaseNamespace([
    'ALLOW_UNKNOWN', 'ALLOW_BINARY', 'ALLOW_CERTIFICATE', 'ALLOW_SCOPE',
    'BLOCK_UNKNOWN', 'BLOCK_BINARY', 'BLOCK_CERTIFICATE', 'BLOCK_SCOPE',
    'BUNDLE_BINARY', 'UNKNOWN'])


CLIENT = UppercaseNamespace([
    'BIT9',
    'SANTA',
    'UNKNOWN'])


USER_ROLE = UppercaseNamespace([
    'USER', 'TRUSTED_USER', 'UNTRUSTED_USER', 'SUPERUSER', 'ADMINISTRATOR',
    'SECURITY'])
USER_ROLE.DefineSet('ADMIN_ROLES', [
    USER_ROLE.ADMINISTRATOR, USER_ROLE.SECURITY])


# Different ways of associating events with Upvote users.
# * EXECUTING_USER associate the event with OS user who ran the application that
#     was blocked.
# * HOST_OWNER associates the event with the "owner" of the host on which the
#     event occurred. For Santa, this corresponds to the MachineOwner
#     configuration key. For Bit9, this corresponds the "users" field of the
#     computer entity.
EVENT_CREATION = UppercaseNamespace(['EXECUTING_USER', 'HOST_OWNER'])


# Static state values for requests.
STATE = UppercaseNamespace([

    # Initial state. Voting is allowed
    'UNTRUSTED',

    # Trusted without further votes but still requires host-specific
    # authorization. Voting is allowed.
    'APPROVED_FOR_LOCAL_WHITELISTING',

    # Blockable can run on hosts with an authorization or hosts in monitor mode.
    # Voting is disabled.
    'LIMITED',

    # Allowed globally everywhere without host-specific approval
    # Voting is disabled.
    'GLOBALLY_WHITELISTED',

    # Still in an untrusted state, but an administrator has voted 'no'.
    # Normal users may not vote until the 'no' vote is removed.
    'SUSPECT',

    # Not allowed to run anywhere, can't be voted on
    # Reserved for malware.
    # Voting is disabled.
    # Users who had voted before the binary was banned are no longer trusted.
    'BANNED',

    # Not allowed to run anywhere and users receive no notification.
    # Very limited use.
    # Voting is disabled.
    'SILENT_BANNED',

    # Blockable is whitelisted but pending pick-up by syncing system.
    'PENDING'])

# Certificates have a limited set of states
STATE.DefineSet('CERTIFICATE', [
    STATE.UNTRUSTED, STATE.SUSPECT, STATE.BANNED, STATE.GLOBALLY_WHITELISTED])

STATE.DefineSet('BANNED', [STATE.BANNED, STATE.SILENT_BANNED])
STATE.DefineSet('WHITELISTABLE', [
    STATE.APPROVED_FOR_LOCAL_WHITELISTING, STATE.LIMITED,
    STATE.GLOBALLY_WHITELISTED])
STATE.DefineSet('VOTING_ALLOWED', [
    STATE.UNTRUSTED, STATE.APPROVED_FOR_LOCAL_WHITELISTING])
STATE.DefineSet('VOTING_ALLOWED_ADMIN_ONLY', [STATE.SUSPECT])
STATE.DefineSet('VOTING_PROHIBITED', [
    STATE.PENDING, STATE.LIMITED, STATE.BANNED, STATE.SILENT_BANNED,
    STATE.GLOBALLY_WHITELISTED])


VOTING_PROHIBITED_REASONS = Namespace(tuples=[
    ('ADMIN_ONLY', 'ADMIN_ONLY'),
    ('BLACKLISTED_CERT', 'BLACKLISTED_CERT'),
    ('FLAGGED_BINARY', 'FLAGGED_BINARY'),
    ('FLAGGED_CERT', 'FLAGGED_CERT'),
    ('INSUFFICIENT_PERMISSION', 'INSUFFICIENT_PERMISSION'),
    ('PROHIBITED_STATE', 'PROHIBITED_STATE'),
    ('UPLOADING_BUNDLE', 'UPLOADING_BUNDLE')])


CLIENT_MODE = UppercaseNamespace(['MONITOR', 'LOCKDOWN'])


RULE_TYPE = UppercaseNamespace(['BINARY', 'CERTIFICATE', 'PACKAGE'])


RULE_SCOPE = UppercaseNamespace(['GLOBAL', 'LOCAL'])


RULE_POLICY = UppercaseNamespace([
    'WHITELIST', 'BLACKLIST', 'REMOVE', 'FORCE_INSTALLER',
    'FORCE_NOT_INSTALLER', 'WHITELIST_COMPILER'])
RULE_POLICY.DefineSet('EXECUTION', [
    RULE_POLICY.WHITELIST, RULE_POLICY.BLACKLIST, RULE_POLICY.REMOVE])
RULE_POLICY.DefineSet('INSTALLER', [
    RULE_POLICY.FORCE_INSTALLER, RULE_POLICY.FORCE_NOT_INSTALLER])
RULE_POLICY.DefineSet('BIT9', [
    RULE_POLICY.WHITELIST, RULE_POLICY.BLACKLIST, RULE_POLICY.REMOVE,
    RULE_POLICY.FORCE_INSTALLER, RULE_POLICY.FORCE_NOT_INSTALLER])
RULE_POLICY.DefineSet('SANTA', [
    RULE_POLICY.WHITELIST, RULE_POLICY.BLACKLIST, RULE_POLICY.REMOVE,
    RULE_POLICY.WHITELIST_COMPILER])


EXEMPTION_REASON = UppercaseNamespace(names=[

    # Develops for the macOS platform.
    'DEVELOPER_MACOS',

    # Develops for the iOS platform.
    'DEVELOPER_IOS',

    # Develops compilers, dev tools, etc.
    'DEVELOPER_DEVTOOLS',

    # Develops for personal use.
    'DEVELOPER_PERSONAL',

    # Uses a package manager such as Homebrew.
    'USES_PACKAGE_MANAGER',

    # Is fearful of lockdown mode having a negative impact.
    'FEARS_NEGATIVE_IMPACT',

    # Reason doesn't fall into the above categories. A separate explanation will
    # be provided.
    'OTHER'])


BIT9_ENFORCEMENT_LEVEL = UppercaseNamespace(names=[
    'LOCKDOWN', 'BLOCK_AND_ASK', 'MONITOR', 'DISABLED'])
BIT9_ENFORCEMENT_LEVEL.DefineMap('FROM_INTEGRAL_LEVEL', {
    20: BIT9_ENFORCEMENT_LEVEL.LOCKDOWN,
    30: BIT9_ENFORCEMENT_LEVEL.BLOCK_AND_ASK,
    40: BIT9_ENFORCEMENT_LEVEL.MONITOR,
    80: BIT9_ENFORCEMENT_LEVEL.DISABLED})

BIT9_ENFORCEMENT_LEVEL.DefineMap('TO_POLICY_ID', {})

POLICY_CHECK_OUTCOME = UppercaseNamespace(names=[
    'DENY',
    'APPROVE'
])
POLICY_CHECK_OUTCOME.DefineMap('PRIORITY', {
    POLICY_CHECK_OUTCOME.DENY: 0,
    POLICY_CHECK_OUTCOME.APPROVE: 1,
})

EXEMPTION_STATE = UppercaseNamespace(names=[
    'REQUESTED', 'PENDING', 'APPROVED', 'DENIED', 'ESCALATED', 'CANCELLED',
    'REVOKED', 'EXPIRED'])
EXEMPTION_STATE.DefineSet('OUTCOME', ['APPROVED', 'DENIED', 'ESCALATED'])
EXEMPTION_STATE.DefineMap('VALID_STATE_CHANGES', {
    EXEMPTION_STATE.REQUESTED: set([EXEMPTION_STATE.PENDING]),
    EXEMPTION_STATE.PENDING: set([
        EXEMPTION_STATE.DENIED,
        EXEMPTION_STATE.ESCALATED,
        EXEMPTION_STATE.APPROVED,
        EXEMPTION_STATE.REQUESTED]),
    EXEMPTION_STATE.APPROVED: set([
        EXEMPTION_STATE.CANCELLED,
        EXEMPTION_STATE.REVOKED,
        EXEMPTION_STATE.EXPIRED,
        EXEMPTION_STATE.REQUESTED]),
    EXEMPTION_STATE.DENIED: set([
        EXEMPTION_STATE.ESCALATED,
        EXEMPTION_STATE.REQUESTED]),
    EXEMPTION_STATE.ESCALATED: set([
        EXEMPTION_STATE.APPROVED,
        EXEMPTION_STATE.DENIED]),
    EXEMPTION_STATE.CANCELLED: set([EXEMPTION_STATE.REQUESTED]),
    EXEMPTION_STATE.REVOKED: set([EXEMPTION_STATE.REQUESTED]),
    EXEMPTION_STATE.EXPIRED: set([EXEMPTION_STATE.REQUESTED])})

EXEMPTION_DURATION = UppercaseNamespace(names=[
    'DAY', 'WEEK', 'MONTH', 'YEAR'])

# Map of exemption terms to an integer number of days
# Used to calculate offset for exemption deactivation timestamp
EXEMPTION_DURATION.DefineMap('TO_DAYS', {
    EXEMPTION_DURATION.DAY: 1,
    EXEMPTION_DURATION.WEEK: 7,
    EXEMPTION_DURATION.MONTH: 31,
    EXEMPTION_DURATION.YEAR: 365})

LOCAL_ADMIN = Namespace(tuples=[
    (PLATFORM.WINDOWS, 'NT AUTHORITY\\SYSTEM'),
    (PLATFORM.MACOS, 'root')])

BIGQUERY_DATASET = 'gae_streaming'

BIGQUERY_TABLE = Namespace(tuples=[
    ('BINARY', 'Binary'),
    ('BUNDLE', 'Bundle'),
    ('BUNDLE_BINARY', 'BundleBinary'),
    ('CERTIFICATE', 'Certificate'),
    ('EXECUTION', 'Execution'),
    ('EXEMPTION', 'Exemption'),
    ('HOST', 'Host'),
    ('RULE', 'Rule'),
    ('USER', 'User'),
    ('VOTE', 'Vote')])

HOST_ACTION = UppercaseNamespace(names=[
    'FIRST_SEEN', 'FULL_SYNC', 'MODE_CHANGE', 'USERS_CHANGE', 'COMMENT'])

HOST_MODE = UppercaseNamespace(names=[
    'MONITOR', 'LOCKDOWN', 'DISABLED', 'BLOCK_AND_ASK', 'UNKNOWN'])

BLOCK_ACTION = UppercaseNamespace(names=[
    'FIRST_SEEN', 'SCORE_CHANGE', 'STATE_CHANGE',
    'RESET', 'COMMENT', 'UPLOADED'])

USER_ACTION = UppercaseNamespace(names=[
    'FIRST_SEEN', 'ROLE_CHANGE', 'COMMENT'])

SITE_ALERT_PLATFORM = UppercaseNamespace(names=['MACOS', 'WINDOWS', 'ALL'])

SITE_ALERT_SCOPE = UppercaseNamespace(names=[
    'APPLIST', 'APPDETAIL', 'HOSTLIST', 'EVERYWHERE'])

SITE_ALERT_SEVERITY = UppercaseNamespace(names=['INFO', 'ERROR'])

TASK_QUEUE = Namespace(tuples=[

    # Used for daily Datastore backups.
    ('BACKUP', 'backup'),

    # Used for changes that need to be committed to Bit9.
    ('BIT9_COMMIT_CHANGE', 'bit9-commit-change'),

    # Used for counting the size of the backlog in Bit9.
    ('BIT9_COUNT', 'bit9-count'),

    # Used for pulling new events out of Bit9.
    ('BIT9_PULL', 'bit9-pull'),

    # Used for dispatching event processing tasks onto bit9-event-process.
    ('BIT9_DISPATCH', 'bit9-dispatch'),

    # Used for processing events that have been pulled out of Bit9.
    ('BIT9_PROCESS', 'bit9-process'),

    # Default task queue.
    ('DEFAULT', 'default'),

    # Used for deferring batch query tasks. See gae/datastore/utils.py.
    ('QUERY', 'query'),

    # Used for deferring the collection of VirusTotal metrics.
    ('METRICS', 'metrics'),

    # Used for processing exemption-related tasks.
    ('EXEMPTIONS', 'exemptions'),

    # Used for performing BigQueryRow streaming inserts.
    ('BIGQUERY_STREAMING', 'bigquery-streaming')])
