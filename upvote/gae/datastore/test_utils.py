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

"""Various bits of utility code to make model testing easier."""

import datetime
import random
import string
import uuid

import mock

from google.appengine.api import users
from google.appengine.ext import ndb

from upvote.gae import settings
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import binary as binary_models
from upvote.gae.datastore.models import cert as cert_models
from upvote.gae.datastore.models import event as event_models
from upvote.gae.datastore.models import exemption as exemption_models
from upvote.gae.datastore.models import host as host_models
from upvote.gae.datastore.models import package as package_models
from upvote.gae.datastore.models import policy as policy_models
from upvote.gae.datastore.models import rule as rule_models
from upvote.gae.datastore.models import user as user_models
from upvote.gae.datastore.models import vote as vote_models
from upvote.gae.utils import env_utils
from upvote.gae.utils import user_utils
from upvote.shared import constants


class Error(Exception):
  """Module-level base Exception."""


class NotRunningLocallyError(Error):
  """Raised when calling a method that can only be used on local deployments."""


def RandomInt(low=1000, high=9999):
  return random.randint(low, high)


def RandomString(source, length):
  return ''.join(random.choice(source) for _ in xrange(length))


def RandomLetters(length):
  return RandomString(string.lowercase, length)


def RandomDigits(length):
  return RandomString(string.digits, length)


def RandomHash(length):
  lower_hexdigits = ''.join(set(string.hexdigits.lower()))
  return RandomString(lower_hexdigits, length)


def RandomSHA256():
  return RandomHash(64)


def RandomMD5():
  return RandomHash(32)


def RandomSHA1():
  return RandomHash(40)


def RandomStrings(size):
  return [RandomLetters(8) for _ in xrange(size)]


def RandomInts(size):
  return [RandomInt() for _ in xrange(size)]


def RandomConstant(constant_namespace):
  return random.choice(tuple(constant_namespace.SET_ALL))


def RandomEmail():
  return user_utils.UsernameToEmail('noreply+%s' % RandomLetters(8))


def RandomEmails(count):
  return [RandomEmail() for _ in xrange(count)]


def RandomDatetime():
  """Returns a random datetime that falls within the last 30 days."""
  max_offset_seconds = datetime.timedelta(days=30).total_seconds()
  offset_seconds = random.randint(0, max_offset_seconds)
  return Now() - datetime.timedelta(seconds=offset_seconds)


_NDB_PROPERTY_VALUE_FUNCS = {
    ndb.StringProperty: lambda: RandomLetters(4),
    ndb.DateTimeProperty: RandomDatetime,
    ndb.BooleanProperty: lambda: random.choice([True, False]),
    ndb.IntegerProperty: RandomInt}


def RandomDatastoreEntity(model_cls, **kwargs):
  """Creates a Datastore entity with random required Property values.

  Args:
    model_cls: The ndb.Model to create an entity of.
    **kwargs: Dictionary of properties to pass to the Model constructor.

  Returns:
    The newly-created (and un-persisted) Datastore entity.
  """
  defaults = {}

  # pylint: disable=protected-access
  for prop in model_cls._properties.values():

    property_cls = prop.__class__
    property_name = prop._name

    if prop._choices:
      value_func = lambda prop=prop: random.choice(list(prop._choices))
    else:
      value_func = _NDB_PROPERTY_VALUE_FUNCS.get(property_cls)

    if value_func is not None and property_name != 'class':

      if prop._choices and prop._repeated:
        random_value = [random.choice(list(prop._choices)) for _ in xrange(3)]
      elif prop._choices:
        random_value = random.choice(list(prop._choices))
      elif prop._repeated:
        random_value = [value_func() for _ in xrange(3)]
      else:
        random_value = value_func()

      defaults[property_name] = random_value
  # pylint: enable=protected-access

  defaults.update(kwargs)
  return model_cls(**defaults)


def RandomDatastoreEntities(model_cls, count, **kwargs):
  return [RandomDatastoreEntity(model_cls, **kwargs) for _ in xrange(count)]


def CreateAppEngineUser(email=None):
  email = email or RandomEmail()
  return users.User(email=email)


def Now():
  return datetime.datetime.utcnow()


def CreateBlockableEntity(blockable_cls, **kwargs):
  """Creates a Blockable.

  Args:
    blockable_cls: The Blockable class to create an entity of.
    **kwargs: Dictionary of any Blockable properties to customize.

  Returns:
    The newly-created Blockable entity.
  """
  defaults = {
      'id_type': constants.ID_TYPE.SHA256,
      'file_name': 'file_name_%s' % RandomLetters(4),
      'occurred_dt': Now(),
      'publisher': 'publisher_%s' % RandomLetters(4),
      'product_name': 'product_name_%s' % RandomLetters(4),
      'version': '1.0',
      'state': constants.STATE.UNTRUSTED}
  defaults.update(kwargs.copy())

  # Ensure that id and blockable_hash are both present.
  binary_hash = defaults.get('id', None)
  if binary_hash is None:
    binary_hash = defaults.get('blockable_hash', RandomSHA256())
  defaults['id'] = binary_hash
  defaults['blockable_hash'] = binary_hash

  return blockable_cls(**defaults)


def CreateBlockable(**kwargs):
  """Creates a Blockable.

  Args:
    **kwargs: Dictionary of any Blockable properties to customize.

  Returns:
    The newly-created Blockable entity.
  """
  blockable = CreateBlockableEntity(binary_models.Blockable, **kwargs)
  blockable.put()
  return blockable


def CreateBinary(**kwargs):
  """Creates a Binary.

  Args:
    **kwargs: Dictionary of any Binary properties to customize.

  Returns:
    The newly-created Binary entity.
  """
  blockable = CreateBlockableEntity(binary_models.Binary, **kwargs)
  blockable.put()
  return blockable


def CreateBit9Binary(**kwargs):
  """Creates a Bit9Binary.

  Args:
    **kwargs: Dictionary of any Blockable properties to customize.

  Returns:
    The newly-created Bit9Binary entity.
  """
  defaults = {
      'detected_installer': False,
      'file_catalog_id': RandomDigits(5),
      'md5': RandomMD5(),
      'sha1': RandomSHA1(),
      'occurred_dt': Now()}
  defaults.update(kwargs.copy())

  bit9_blockable = CreateBlockableEntity(binary_models.Bit9Binary, **defaults)
  bit9_blockable.put()
  return bit9_blockable


def CreateBit9Certificate(**kwargs):

  defaults = {
      'valid_from_dt': Now(),
      'valid_to_dt': Now()}
  defaults.update(kwargs.copy())

  bit9_cert = CreateBlockableEntity(cert_models.Bit9Certificate, **defaults)
  bit9_cert.put()
  return bit9_cert


def CreateBit9Certificates(count, **kwargs):
  return [CreateBit9Certificate(**kwargs) for _ in xrange(count)]


def CreateSantaBlockable(**kwargs):
  santa_blockable = CreateBlockableEntity(
      binary_models.SantaBlockable, **kwargs)
  santa_blockable.put()
  return santa_blockable


def CreateSantaCertificate(**kwargs):
  santa_cert = CreateBlockableEntity(cert_models.SantaCertificate, **kwargs)
  santa_cert.put()
  return santa_cert


def CreateSantaBundle(bundle_binaries=None, **kwargs):
  """Create a SantaBundle entity."""
  defaults = {
      'name': 'bundle_name_%s' % RandomLetters(3),
      'bundle_id': '.'.join(RandomLetters(3) for _ in xrange(3)),
      'version': '.'.join(RandomDigits(1) for _ in xrange(3)),
      'short_version': '.'.join(RandomDigits(1) for _ in xrange(3)),
      'binary_count': len(bundle_binaries) if bundle_binaries else 1,
      'uploaded_dt': Now()}
  defaults.update(kwargs.copy())

  santa_bundle = CreateBlockableEntity(package_models.SantaBundle, **defaults)
  santa_bundle.put()

  # Create the SantaBundleBinary entities, if any bundle binaries were
  # specified.
  if bundle_binaries:
    entities = []
    for binary in bundle_binaries:
      entity = package_models.SantaBundleBinary.Generate(
          santa_bundle.key, binary.key, cert_key=binary.cert_key,
          file_name=binary.file_name, rel_path='Content/MacOS')
      entities.append(entity)

    ndb.put_multi(entities)

  return santa_bundle


def CreateBit9Binaries(count, **kwargs):
  """Creates a list of Bit9Binary entities.

  Args:
    count: The number of Bit9Binary entities to create.
    **kwargs: Dictionary of any Blockable properties to customize.

  Returns:
    A list of newly-created Bit9Binary entities.
  """
  return [CreateBit9Binary(**kwargs) for _ in xrange(count)]


def CreateSantaBlockables(count, **kwargs):
  """Creates a list of SantaBlockables."""
  return [CreateSantaBlockable(**kwargs) for _ in xrange(count)]


def CreateVote(blockable, **kwargs):
  """Creates a Vote for the given Blockable.

  Args:
    blockable: The Blockable to vote for.
    **kwargs: dict, Any Vote properties to customize.

  Returns:
    The newly-created Vote entity.
  """
  defaults = {
      'user_email': RandomEmail(),
      'weight': 1,
      'was_yes_vote': True,
      'candidate_type': constants.RULE_TYPE.BINARY
  }
  defaults.update(kwargs)

  vote = vote_models.Vote(**defaults)
  vote.key = vote_models.Vote.GetKey(
      blockable.key, ndb.Key(user_models.User, defaults['user_email']))
  vote.put()
  return vote


def CreateVotes(blockable, count, **kwargs):
  """Creates multiple Vote entites for the given Blockable.

  Args:
    blockable: The Blockable to create Votes for.
    count: int, The number of Votes to create.
    **kwargs: dict, Any Vote properties to customize.

  Returns:
    The newly-created Vote entities.
  """
  return [
      CreateVote(blockable, user_email=RandomEmail(), **kwargs)
      for _ in xrange(count)]


def _CreateEvent(event_cls, blockable, **kwargs):
  """Creates an Event.

  Args:
    event_cls: The Event class to create.
    blockable: The Blockable to create an Event for.
    **kwargs: Dictionary of any host properties to customize.

  Returns:
    The newly created Event.
  """
  defaults = {
      'blockable_key': blockable.key,
      'event_type': constants.EVENT_TYPE.UNKNOWN,
      'executing_user': RandomLetters(8),
      'host_id': str(RandomInt())}
  defaults.update(kwargs.copy())
  event = event_cls(**defaults)
  event.put()
  return event


def CreateEvent(blockable, **kwargs):
  """Creates an Event for the given Blockable.

  Args:
    blockable: The Blockable to create an Event for.
    **kwargs: Dictionary of any Event properties to customize.

  Returns:
    The newly-created Event entity.
  """
  return _CreateEvent(event_models.Event, blockable, **kwargs)


def CreateSantaEvent(blockable, **kwargs):
  defaults = {
      'event_type': constants.EVENT_TYPE.UNKNOWN}
  defaults.update(kwargs)
  return _CreateEvent(event_models.SantaEvent, blockable, **defaults)


def CreateBit9Event(blockable, **kwargs):
  defaults = {
      'bit9_id': RandomInt(),
  }
  defaults.update(kwargs)
  return _CreateEvent(event_models.Bit9Event, blockable, **defaults)


def CreateEvents(blockable, event_count):
  """Creates multiple Events for the given Blockable.

  Args:
    blockable: The Blockable to create an Event for.
    event_count: The number of Events to create.

  Returns:
    The newly-created Event entities.
  """
  return [CreateEvent(blockable) for _ in xrange(event_count)]


def CreateSantaEvents(blockable, event_count):
  return [CreateSantaEvent(blockable) for _ in xrange(event_count)]


def CreateBit9Events(blockable, event_count):
  return [CreateBit9Event(blockable) for _ in xrange(event_count)]


@mock.patch.object(
    settings.ProdEnv, 'ENABLE_BIGQUERY_STREAMING',
    new_callable=mock.PropertyMock(return_value=False))
def CreateUser(_, admin=False, **kwargs):
  """Creates an User entity.

  Args:
    admin: Whether or not administrative privileges should be assigned.
    **kwargs: Dictionary of any user properties to customize.

  Returns:
    The newly created User.
  """
  email = kwargs.pop('email', None) or RandomEmail()
  roles = set(kwargs.pop('roles', []))

  # Create an User entity if one doesn't exist, and update the resulting
  # entity with any overridden properties.
  user = user_models.User.GetOrInsert(email_addr=email)
  if kwargs:
    user.populate(**kwargs)
    user.put()

  # Update the entity with custom roles, if specified.
  if admin:
    roles |= constants.USER_ROLE.SET_ADMIN_ROLES
  if roles:
    user_models.User.SetRoles(email, roles)

  return user_models.User.GetOrInsert(email_addr=email)


def CreateUsers(user_count, **kwargs):
  return [CreateUser(**kwargs) for _ in xrange(user_count)]


def _GenerateUnusedEntityId(model_cls, id_gen_func):
  entity_id = id_gen_func()
  while model_cls.get_by_id(entity_id) is not None:
    entity_id = id_gen_func()
  return entity_id


def _CreateHost(host_cls, **kwargs):
  """Creates a Host.

  Args:
    host_cls: The host class to create.
    **kwargs: Dictionary of any host properties to customize.

  Returns:
    The newly created host.
  """
  defaults = {
      'id': str(uuid.uuid4()).upper(),
      'hostname': 'host_%s' % RandomLetters(4)
  }
  defaults.update(kwargs.copy())
  defaults['id'] = host_models.Host.NormalizeId(defaults['id'])

  new_host = host_cls(**defaults)
  new_host.put()

  return new_host


def CreateSantaHost(**kwargs):
  """Creates a SantaHost.

  Args:
    **kwargs: Dictionary of properties to customize.

  Returns:
    Newly created SantaHost.
  """
  return _CreateHost(host_models.SantaHost, **kwargs)


def CreateBit9Host(**kwargs):
  """Creates a Bit9Host.

  Args:
    **kwargs: Dictionary of properties to customize.

  Returns:
    Newly created Bit9Host.
  """
  id_gen_func = lambda: str(RandomInt(high=100000))
  defaults = {'id': _GenerateUnusedEntityId(host_models.Bit9Host, id_gen_func)}
  defaults.update(kwargs.copy())

  return _CreateHost(host_models.Bit9Host, **defaults)


def CreateSantaHosts(count, **kwargs):
  """Creates a list of SantaHosts."""
  return [CreateSantaHost(**kwargs) for _ in xrange(count)]


def CreateBit9Hosts(count, **kwargs):
  """Creates a list of Bit9Hosts."""
  return [CreateBit9Host(**kwargs) for _ in xrange(count)]


def CreateBlacklist(**kwargs):
  """Creates a Blacklist.

  Args:
    **kwargs: Dictionary of properties to customize.

  Returns:
    Newly created Blacklist.
  """
  defaults = {
      'regex': '[Rr][Ee][Gg][Ee][Xx]'}
  defaults.update(kwargs.copy())
  blacklist = binary_models.Blacklist(**defaults)
  blacklist.put()
  return blacklist


def CreateRuleEntity(rule_cls, blockable_key, **kwargs):
  """Creates a Rule.

  Args:
    rule_cls: The Rule class to create an entity of.
    blockable_key: The key of the blockable the rule relates to.
    **kwargs: Dictionary of properties to customize.

  Returns:
    Newly created Rule.
  """
  defaults = {
      'rule_type': constants.RULE_TYPE.BINARY,
      'policy': constants.RULE_POLICY.BLACKLIST,
      'in_effect': True}
  defaults.update(kwargs.copy())
  return rule_cls(parent=blockable_key, **defaults)


def CreateSantaRule(blockable_key, **kwargs):
  santa_rule = CreateRuleEntity(rule_models.SantaRule, blockable_key, **kwargs)
  santa_rule.put()
  return santa_rule


def CreateSantaRules(blockable_key, count, **kwargs):
  return [CreateSantaRule(blockable_key, **kwargs) for _ in xrange(count)]


def CreateBit9Rule(blockable_key, **kwargs):
  defaults = {
      'is_committed': False,
      'is_fulfilled': False}
  defaults.update(kwargs.copy())
  bit9_rule = CreateRuleEntity(rule_models.Bit9Rule, blockable_key, **defaults)
  bit9_rule.put()
  return bit9_rule


def CreateBit9Rules(blockable_key, count, **kwargs):
  return [CreateBit9Rule(blockable_key, **kwargs) for _ in xrange(count)]


def CreateRuleChangeSet(blockable_key, **kwargs):
  defaults = {
      'change_type': constants.RULE_POLICY.BLACKLIST,
      'rule_keys': []
  }
  defaults.update(kwargs.copy())
  change = rule_models.RuleChangeSet(parent=blockable_key, **defaults)
  change.put()
  return change


def CreateBit9Policy(**kwargs):
  """Creates a Bit9Policy.

  Args:
    **kwargs: Dictionary of any policy properties to customize.

  Returns:
    The newly created host.
  """
  id_gen_func = lambda: RandomDigits(16)
  defaults = {
      'id': _GenerateUnusedEntityId(policy_models.Bit9Policy, id_gen_func),
      'name': RandomLetters(16),
      'enforcement_level': constants.BIT9_ENFORCEMENT_LEVEL.LOCKDOWN}
  defaults.update(kwargs.copy())

  new_policy = policy_models.Bit9Policy(**defaults)
  new_policy.put()

  return new_policy


def CreateExemption(
    host_id, deactivation_dt=None, reason=None, other_text=None,
    initial_state=constants.EXEMPTION_STATE.REQUESTED):
  """Creates a test Exemption entity."""

  key = exemption_models.Exemption.CreateKey(host_id)
  deactivation_dt = (
      deactivation_dt if deactivation_dt else datetime.datetime.utcnow())
  reason = reason if reason else 'Some fake reason'
  details = [reason, other_text] if other_text else [reason]
  record = exemption_models.Record(state=initial_state, details=details)
  history = [record]

  return exemption_models.Exemption(
      key=key,
      deactivation_dt=deactivation_dt,
      state=initial_state,
      history=history).put()


def CreateTestEntities(email_addr):
  """Create some test Datastore data if specified, but only if running locally.

  Note that this code doesn't (and shouldn't) delete any existing entities.
  The risk of such code being accidentally triggered in prod is too great, so
  if local entities need to be deleted, use the local Datastore viewer (e.g.
  http://127.0.0.1:8000/datastore).

  Args:
    email_addr: Email address of the local users for whom test data should
        be created.

  Raises:
    NotRunningLocallyError: if called anywhere other than a local deployment.
  """
  if not env_utils.RunningLocally():
    raise NotRunningLocallyError

  # Create a user entity with all available roles.
  user = user_models.User.GetOrInsert(email_addr=email_addr)
  user_models.User.SetRoles(email_addr, constants.USER_ROLE.SET_ALL)

  username = user_utils.EmailToUsername(email_addr)

  # Create associated SantaHosts for the user.
  santa_hosts = CreateSantaHosts(2, primary_user=username)

  # For each SantaHost, create some SantaEvents.
  for santa_host in santa_hosts:
    for santa_blockable in CreateSantaBlockables(5):

      parent_key = datastore_utils.ConcatenateKeys(
          user.key, santa_host.key, santa_blockable.key)
      CreateSantaEvent(
          santa_blockable,
          executing_user=username,
          event_type=constants.EVENT_TYPE.BLOCK_BINARY,
          host_id=santa_host.key.id(),
          parent=parent_key)

  # Create associated Bit9Hosts for the user.
  bit9_hosts = CreateBit9Hosts(2, users=[username])

  # For each Bit9Host, create some Bit9Events.
  for bit9_host in bit9_hosts:
    for bit9_binary in CreateBit9Binaries(5):

      parent_key = datastore_utils.ConcatenateKeys(
          user.key, bit9_host.key, bit9_binary.key)
      CreateBit9Event(
          bit9_binary,
          executing_user=username,
          event_type=constants.EVENT_TYPE.BLOCK_BINARY,
          host_id=bit9_host.key.id(),
          parent=parent_key)
