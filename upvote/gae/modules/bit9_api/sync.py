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

"""Handlers for retrieving Bit9 event data via RPC."""

import datetime
import httplib
import logging
import re
import time

from google.appengine.ext import deferred
from google.appengine.ext import ndb

from common import memcache_decorator
from common import datastore_locks

from upvote.gae.datastore import utils as model_utils
from upvote.gae.datastore.models import base
from upvote.gae.datastore.models import bigquery
from upvote.gae.datastore.models import bit9
from upvote.gae.lib.analysis import metrics
from upvote.gae.modules.bit9_api import change_set
from upvote.gae.modules.bit9_api import constants as bit9_constants
from upvote.gae.modules.bit9_api import rest_utils
from upvote.gae.modules.bit9_api import monitoring
from upvote.gae.modules.bit9_api import utils
from upvote.gae.modules.bit9_api.api import api
from upvote.gae.shared.common import query_utils
from upvote.gae.shared.common import user_map
from upvote.gae.taskqueue import utils as taskqueue_utils
from upvote.gae.utils import time_utils
from upvote.shared import constants

# Automatic scaling sets a 10 minute deadline for tasks queues. We specify a
# task duration slightly less than that in order to allow enough time for
# everything to finish cleanly (e.g. a 30 second request). See also:
# https://cloud.google.com/appengine/docs/standard/java/taskqueue/#push_queues_and_pull_queues
_TASK_DURATION = datetime.timedelta(minutes=9, seconds=15)

_PULL_LOCK_ID = 'pull_events_lock'
_PULL_LOCK_TIMEOUT = int(
    datetime.timedelta(minutes=10, seconds=30).total_seconds())
_PULL_LOCK_MAX_ACQUIRE_ATTEMPTS = 5

_PULL_BATCH_SIZE = 128

# The lock timeout should be just over the 10 minute task queue timeout, to
# ensure that the lock isn't released prematurely during task execution, but
# also is not held onto longer than is absolutely necessary.
_PROCESS_LOCK_TIMEOUT = int(
    datetime.timedelta(minutes=10, seconds=30).total_seconds())
_PROCESS_LOCK_MAX_ACQUIRE_ATTEMPTS = 1


_CERT_MEMCACHE_KEY = 'bit9_cert_%s'
_CERT_MEMCACHE_TIMEOUT = datetime.timedelta(days=7).total_seconds()

_LOCAL_RULE_COPY_LIMIT = 250

_GET_CERT_ATTEMPTS = 3


class Error(Exception):
  """Base error."""


class MalformedCertificate(Error):
  """A malformed cert has been received from Bit9."""


class _UnsyncedEvent(ndb.Model):
  """Model for storing unsynced Event protobufs.

  Attributes:
    event: An api.Event API response dict object with FileCatalog and Computer
        expansions.
    signing_chain: List[api.Certificate] the binary's signing chain.
    occurred_dt: Timestamp of when this event occurred on the client.
    sha256: SHA256 string from the Event proto. Added primarily for easier
        debugging and investigating.
    bit9_id: The Bit9 database entity ID associated with this event.
  """
  event = ndb.JsonProperty()
  signing_chain = ndb.JsonProperty()
  occurred_dt = ndb.DateTimeProperty()
  sha256 = ndb.StringProperty()
  host_id = ndb.IntegerProperty()
  bit9_id = ndb.IntegerProperty()

  @classmethod
  def Generate(cls, event, signing_chain):
    file_catalog = event.get_expand(api.Event.file_catalog_id)
    computer = event.get_expand(api.Event.computer_id)
    return cls(
        event=event._obj_dict,  # pylint: disable=protected-access
        signing_chain=[cert.to_raw_dict() for cert in signing_chain],
        occurred_dt=event.timestamp,
        sha256=file_catalog.sha256,
        host_id=computer.id,
        bit9_id=event.id)


def _Now():
  """Returns the current datetime. Primarily for easier unit testing."""
  return datetime.datetime.utcnow()


def GetLastSyncedId():
  event = bit9.Bit9Event.query().order(-bit9.Bit9Event.bit9_id).get()
  unsynced_event = _UnsyncedEvent.query().order(-_UnsyncedEvent.bit9_id).get()
  return max(
      event and event.bit9_id, unsynced_event and unsynced_event.bit9_id, 0)


def BuildEventSubtypeFilter():
  filter_expr = None
  for subtype in bit9_constants.SUBTYPE.SET_ALL:
    new_operand = (api.Event.subtype == subtype)
    filter_expr = filter_expr | new_operand if filter_expr else new_operand
  return filter_expr


@memcache_decorator.Cached(
    expire_time=_CERT_MEMCACHE_TIMEOUT,
    create_key_func=lambda f, key, args, kwargs: _CERT_MEMCACHE_KEY % args[0],
    namespace=None)
def _GetCertificate(cert_id):
  """Gets a certificate entity."""
  for _ in xrange(_GET_CERT_ATTEMPTS):
    cert = api.Certificate.get(cert_id, utils.CONTEXT)

    # Attempt to parse the cert before caching it, in case the related
    # fileCatalog contains an "embedded signer". In such cases, the fileCatalog
    # contains a certificateId, but the actual cert data comes back empty,
    # causing breakage here.
    try:
      cert.to_raw_dict()
    except Exception:  # pylint: disable=broad-except
      message = 'Unable to parse Certificate %s' % cert_id
      logging.exception(message)
    else:
      return cert

  raise MalformedCertificate(message)


def _GetSigningChain(cert_id):
  """Gets the signing chain of a leaf certificate.

  Args:
    cert_id: int, The id of the certificate to get the signing chain of.

  Returns:
    The signing chain of the certificate objects in Leaf->Root order.
  """
  signing_chain = []
  next_cert_id = cert_id

  while next_cert_id:
    cert = _GetCertificate(next_cert_id)
    signing_chain.append(cert)
    next_cert_id = cert.parent_certificate_id

  return signing_chain


def GetEvents(last_synced_id, limit=_PULL_BATCH_SIZE):
  """Get one or more events from Bit9.

  If events have been retrieved in the last five minutes, gets all recent
  events. Otherwise, gets events in the oldest unseen five minute interval,
  so as not to overwhelm Bit9.

  Args:
    last_synced_id: The ID of the most recent event that was successfully
        synced to Upvote.
    limit: int, If provided, the maximum number of events to pull from the
        events table. Otherwise, the module default is used.

  Returns:
    A list of events not yet pushed to Upvote.
  """
  logging.info('Retrieving events after ID=%s (Max %s)', last_synced_id, limit)
  events = (api.Event.query()
            .filter(api.Event.id > last_synced_id)
            .filter(api.Event.file_catalog_id > 0)
            .filter(BuildEventSubtypeFilter())
            .expand(api.Event.file_catalog_id)
            .expand(api.Event.computer_id)
            .limit(limit)
            .order(api.Event.id)
            .execute(utils.CONTEXT))
  logging.info('Retrieved %d event(s)', len(events))

  event_cert_tuples = []
  for event in events:
    logging.info('Constructing event %s', event.id)
    logging.info('Retrieving fileCatalog %s', event.file_catalog_id)

    file_catalog = event.get_expand(api.Event.file_catalog_id)
    if file_catalog is None:
      logging.warning('Skipping event %s (No fileCatalog found)', event.id)
      monitoring.events_skipped.Increment()
      continue

    # At bare minimum we need a SHA256 out of the fileCatalog, so if it's not
    # there we have to skip this event.
    if not file_catalog.sha256:
      logging.warning('Skipping event %s (Incomplete fileCatalog)', event.id)
      monitoring.events_skipped.Increment()
      continue

    logging.info('Retrieving computer %s', event.computer_id)
    computer = event.get_expand(api.Event.computer_id)
    if computer is None:
      logging.warning('Skipping event %s (No computer found)', event.id)
      monitoring.events_skipped.Increment()
      continue

    try:
      signing_chain = _GetSigningChain(file_catalog.certificate_id)

    # If a MalformedCertificate makes it all the way out here, we've already
    # retried the retrieval a number of times, and have likely hit another
    # fileCatalog containing an "embedded signer". We have to skip this
    # particular event, otherwise event syncing will halt.
    except MalformedCertificate:
      logging.error(
          ('Failed to retrieve signing chain for fileCatalog %s. '
           'Skipping event %s.'), event.file_catalog_id, event.id)
      monitoring.events_skipped.Increment()
      continue

    # If signing chain retrieval fails for any other reason, just return the
    # events constructed so far.
    except Exception as e:  # pylint: disable=broad-except
      logging.exception('Signing chain retrieval failed: %s', e)
      return event_cert_tuples

    event_cert_tuples.append((event, signing_chain))

  return event_cert_tuples


def Pull(batch_size=_PULL_BATCH_SIZE):
  """Retrieve events to sync from Bit9.

  Args:
    batch_size: int, The number of events to retrieve in each batch.
  """
  total_pull_count = 0
  start_time = _Now()
  logging.info('Starting a new pull task')

  try:
    with datastore_locks.DatastoreLock(
        _PULL_LOCK_ID, default_timeout=_PULL_LOCK_TIMEOUT,
        default_max_acquire_attempts=_PULL_LOCK_MAX_ACQUIRE_ATTEMPTS):
      while time_utils.TimeRemains(start_time, _TASK_DURATION):
        last_synced_id = GetLastSyncedId()
        logging.info('Syncing from ID=%s', last_synced_id)

        # Make an API call for a batch of events. If it fails, just log it and
        # try again.
        try:
          event_tuples = GetEvents(last_synced_id, batch_size)
        except Exception as e:  # pylint: disable=broad-except
          logging.warning('Event retrieval failed: %s', e)
          continue

        pull_count = len(event_tuples)
        total_pull_count += pull_count
        logging.info(
            'Retrieved %d events (%d events total)', pull_count,
            total_pull_count)
        monitoring.events_pulled.IncrementBy(pull_count)

        # Persist an _UnsyncedEvent for each retrieved Event proto.
        ndb.put_multi(
            _UnsyncedEvent.Generate(event, signing_chain)
            for event, signing_chain in event_tuples)

        # Briefly pause between requests in order to avoid hammering the Bit9
        # server too hard.
        time.sleep(0.25)
  except datastore_locks.AcquireLockError:
    logging.debug('Unable to acquire datastore lock')


def Dispatch():
  """Dispatches per-host tasks onto the event processing queue."""
  total_dispatch_count = 0
  logging.info('Starting a new dispatch task')

  # Query for all distinct host_id values among the _UnsyncedEvents, in batches,
  # either until we run out, or the task nears its deadline.
  query = _UnsyncedEvent.query(
      projection=[_UnsyncedEvent.host_id], distinct=True)
  for event_page in query_utils.Paginate(query, page_size=25):
    host_ids = [event.host_id for event in event_page]
    for host_id in host_ids:
      deferred.defer(Process, host_id, _queue=constants.TASK_QUEUE.BIT9_PROCESS)
      total_dispatch_count += 1

  logging.info('Dispatched %d task(s)', total_dispatch_count)


def Process(host_id):
  """Processes _UnsyncedEvents for a single Windows host.

  Args:
    host_id: The integer ID of this host in Bit9.
  """
  try:

    with datastore_locks.DatastoreLock(
        'bit9-process-%d' % host_id, default_timeout=_PROCESS_LOCK_TIMEOUT,
        default_max_acquire_attempts=_PROCESS_LOCK_MAX_ACQUIRE_ATTEMPTS):

      total_process_count = 0
      start_time = _Now()
      logging.info('Starting a new processing task for %d', host_id)

      # Query for all _UnsyncedEvents that belong to the given host, in batches,
      # and process them until we run out, or the task nears its deadline.
      query = (_UnsyncedEvent.query(_UnsyncedEvent.host_id == host_id)
               .order(_UnsyncedEvent.bit9_id))
      event_pages = query_utils.Paginate(query, page_size=25)
      event_page = next(event_pages, None)
      while time_utils.TimeRemains(start_time, _TASK_DURATION) and event_page:
        for unsynced_event in event_page:
          event = api.Event.from_dict(unsynced_event.event)
          signing_chain = [
              api.Certificate.from_dict(cert)
              for cert in unsynced_event.signing_chain]
          file_catalog = event.get_expand(api.Event.file_catalog_id)
          computer = event.get_expand(api.Event.computer_id)

          # Persist the event data.
          persist_futures = [
              _PersistBit9Certificates(signing_chain),
              _PersistBit9Binary(event, file_catalog, signing_chain),
              _PersistBanNote(file_catalog),
              _PersistBit9Host(computer, event.timestamp),
              _PersistBit9Events(event, file_catalog, computer, signing_chain)
          ]
          ndb.Future.wait_all(persist_futures)
          for persist_future in persist_futures:
            persist_future.check_success()

          # Now that the event sync has completed successfully, remove the
          # intermediate proto entity.
          unsynced_event.key.delete()

          monitoring.events_processed.Increment()
          total_process_count += 1

        event_page = next(event_pages, None)

    logging.info('Processed %d event(s)', total_process_count)

  except datastore_locks.AcquireLockError:
    logging.debug('Unable to acquire datastore lock')


def _PersistBit9Certificates(signing_chain):
  """Creates Bit9Certificates from the given Event protobuf.

  Args:
    signing_chain: List[api.Certificate] the signing chain of the event.

  Returns:
    An ndb.Future that resolves when all certs are created.
  """
  if not signing_chain:
    return model_utils.GetNoOpFuture()

  to_create = []
  for cert in signing_chain:
    thumbprint = cert.thumbprint
    existing_cert = bit9.Bit9Certificate.get_by_id(thumbprint)
    if existing_cert is None:
      cert = bit9.Bit9Certificate(
          id=thumbprint,
          id_type=cert.thumbprint_algorithm,
          valid_from_dt=cert.valid_from,
          valid_to_dt=cert.valid_to)

      cert.PersistRow(constants.BLOCK_ACTION.FIRST_SEEN, cert.recorded_dt)

      to_create.append(cert)

  futures = ndb.put_multi_async(to_create)
  return model_utils.GetMultiFuture(futures)


def _GetCertKey(signing_chain):
  fingerprint = signing_chain[0].thumbprint if signing_chain else None
  return ndb.Key(bit9.Bit9Certificate, fingerprint) if fingerprint else None


@ndb.tasklet
def _CheckAndResolveInstallerState(blockable_key, bit9_policy):
  """Ensures Bit9's installer state is consistent with Upvote policy.

  If there is no Upvote policy or the existing policy conflicts with Bit9's, the
  function creates rules to reflect Bit9's policy.

  Args:
    blockable_key: The key of the blockable that was blocked.
    bit9_policy: RULE_POLICY.SET_INSTALLER, The installer force policy reported
        by Bit9.

  Yields:
    Whether the installer state was changed.
  """
  logging.info(
      'Detected forced installer policy in Bit9 for ID=%s: policy=%s',
      blockable_key.id(), bit9_policy)
  assert ndb.in_transaction(), 'Policy changes require a transaction'

  # pylint: disable=g-explicit-bool-comparison
  installer_query = bit9.Bit9Rule.query(
      bit9.Bit9Rule.in_effect == True,
      ndb.OR(
          bit9.Bit9Rule.policy == constants.RULE_POLICY.FORCE_INSTALLER,
          bit9.Bit9Rule.policy == constants.RULE_POLICY.FORCE_NOT_INSTALLER),
      ancestor=blockable_key)
  # pylint: enable=g-explicit-bool-comparison
  installer_rule = yield installer_query.get_async()
  logging.info(
      'Forced installer policy in Upvote for ID=%s: policy=%s',
      blockable_key.id(), (
          'NONE' if installer_rule is None else installer_rule.policy))

  has_existing_rule = installer_rule is not None
  has_conflicting_rule = (
      has_existing_rule and
      installer_rule.is_committed and
      installer_rule.policy != bit9_policy)

  if has_existing_rule and not has_conflicting_rule:
    # The existing rule matches the forced Bit9 policy so no rules need to be
    # created.
    raise ndb.Return(False)
  elif has_conflicting_rule:
    # If there is a conflicting policy in Upvote, disable it so the new one can
    # take effect.
    logging.warning('Forced installer status in Bit9 conflicts with Upvote')

    installer_rule.in_effect = False
    yield installer_rule.put_async()

  logging.info('Importing detected forced installer status from Bit9')

  # Create a rule to reflect the policy in Bit9. It's marked committed and
  # fulfilled because the data's already in Bit9, after all.
  new_rule = bit9.Bit9Rule(
      rule_type=constants.RULE_TYPE.BINARY, in_effect=True, is_committed=True,
      is_fulfilled=True, policy=bit9_policy, parent=blockable_key)
  yield new_rule.put_async()

  raise ndb.Return(True)


@ndb.transactional_tasklet
@taskqueue_utils.GroupTransactionalTaskletDefers
def _PersistBit9Binary(event, file_catalog, signing_chain):
  """Creates or updates a Bit9Binary from the given Event protobuf."""
  changed = False

  # Grab the corresponding Bit9Binary.
  bit9_binary = yield bit9.Bit9Binary.get_by_id_async(file_catalog.sha256)

  detected_installer = bool(
      file_catalog.file_flags &
      bit9_constants.FileFlags.DETECTED_INSTALLER)
  is_installer = (
      rest_utils.GetEffectiveInstallerState(file_catalog.file_flags))

  # Doesn't exist? Guess we better fix that.
  if bit9_binary is None:
    logging.info('Creating new Bit9Binary')

    bit9_binary = bit9.Bit9Binary(
        id=file_catalog.sha256,
        id_type=bit9_constants.SHA256_TYPE.MAP_TO_ID_TYPE[
            file_catalog.sha256_hash_type],
        blockable_hash=file_catalog.sha256,
        file_name=event.file_name,
        company=file_catalog.company,
        product_name=file_catalog.product_name,
        version=file_catalog.product_version,
        cert_key=_GetCertKey(signing_chain),
        occurred_dt=event.timestamp,
        sha1=file_catalog.sha1,
        product_version=file_catalog.product_version,
        first_seen_name=file_catalog.file_name,
        first_seen_date=file_catalog.date_created,
        first_seen_path=file_catalog.path_name,
        first_seen_computer=str(file_catalog.computer_id),
        publisher=file_catalog.publisher,
        file_type=file_catalog.file_type,
        md5=file_catalog.md5,
        file_size=file_catalog.file_size,
        detected_installer=detected_installer,
        is_installer=is_installer,
        file_catalog_id=str(file_catalog.id))

    bit9_binary.PersistRow(
        constants.BLOCK_ACTION.FIRST_SEEN,
        bit9_binary.recorded_dt)
    metrics.DeferLookupMetric(
        file_catalog.sha256, constants.ANALYSIS_REASON.NEW_BLOCKABLE)
    changed = True

  # If the file catalog ID has changed, update it.
  if (not bit9_binary.file_catalog_id or
      bit9_binary.file_catalog_id != str(file_catalog.id)):
    bit9_binary.file_catalog_id = str(file_catalog.id)
    changed = True

  # Binary state comes from clients, which may have outdated policies. Only
  # update Bit9Binary state if the client claims BANNED and the
  # Bit9Binary is still UNTRUSTED.
  if (event.subtype == bit9_constants.SUBTYPE.BANNED and
      bit9_binary.state == constants.STATE.UNTRUSTED):
    logging.info(
        'Changing Bit9Binary state from %s to %s', bit9_binary.state,
        constants.STATE.BANNED)
    bit9_binary.state = constants.STATE.BANNED

    bit9_binary.PersistRow(
        constants.BLOCK_ACTION.STATE_CHANGE, event.timestamp)
    changed = True

  if bit9_binary.detected_installer != detected_installer:
    bit9_binary.detected_installer = detected_installer
    bit9_binary.is_installer = bit9_binary.CalculateInstallerState()
    changed = True

  # Create installer Rules for Bit9Binary installer status if it's been forced
  # one way or the other in Bit9.
  marked = file_catalog.file_flags & bit9_constants.FileFlags.MARKED_INSTALLER
  marked_not = (
      file_catalog.file_flags & bit9_constants.FileFlags.MARKED_NOT_INSTALLER)
  if marked or marked_not:
    bit9_policy = (
        constants.RULE_POLICY.FORCE_INSTALLER
        if marked
        else constants.RULE_POLICY.FORCE_NOT_INSTALLER)
    changed_installer_state = yield _CheckAndResolveInstallerState(
        bit9_binary.key, bit9_policy)
    if changed_installer_state:
      bit9_binary.is_installer = (
          bit9_policy == constants.RULE_POLICY.FORCE_INSTALLER)
    changed = changed_installer_state or changed

  # Only persist if needed.
  if changed:
    logging.info('Attempting to put Bit9Binary...')
    yield bit9_binary.put_async()

  # Indicate whether there was a change, primarily for better unit testing.
  raise ndb.Return(changed)


def _PersistBanNote(file_catalog):
  """Creates a Note entity containing a ban description if needed."""

  tuples = [
      (file_catalog.certificate_state, 'certificate'),
      (file_catalog.file_state, 'file'),
      (file_catalog.publisher_state, 'publisher')]

  ban_strings = sorted([
      'Banned by %s' % string
      for state, string in tuples
      if state == bit9_constants.APPROVAL_STATE.BANNED])

  if ban_strings:
    full_message = '\n'.join(ban_strings)

    blockable_key = ndb.Key(bit9.Bit9Binary, file_catalog.sha256)
    note_key = base.Note.GenerateKey(full_message, blockable_key)

    if note_key.get() is None:
      logging.info(
          'Persisting new ban Note for %s: %s', file_catalog.sha256,
          ', '.join(ban_strings))
      note = base.Note(key=note_key, message=full_message)
      return note.put_async()

  return model_utils.GetNoOpFuture()


@ndb.tasklet
def _CopyLocalRules(user_key, dest_host_id):
  """Copy over a user's local rules to a newly-associated host.

  NOTE: Because of the implementation of local whitelisting on Bit9, many of
  these new copied local rules will likely be initially unfulfilled, that is,
  held in Upvote and not saved to Bit9.

  Args:
    user_key: str, The user for whom the rules will be copied.
    dest_host_id: str, The ID of the host for which the new rules will be
        created.
  """
  logging.info('Copying rules for %s to host %s', user_key.id(), dest_host_id)

  username = user_map.EmailToUsername(user_key.id())
  host_query = bit9.Bit9Host.query(bit9.Bit9Host.users == username)
  src_host = yield host_query.get_async()
  if src_host is None:
    raise ndb.Return()
  src_host_id = src_host.key.id()
  assert src_host_id != dest_host_id, (
      'User already associated with target host')

  # Get all local rules from that host, up to a limit. Otherwise, we run the
  # risk of accumulating more and more rules for shared machines that have
  # frequent user turnover. Granted, this isn't a bulletproof fix, but should
  # suffice until a more long-term fix can be completed.
  rules_query = bit9.Bit9Rule.query(
      bit9.Bit9Rule.host_id == src_host_id,
      bit9.Bit9Rule.in_effect == True)  # pylint: disable=g-explicit-bool-comparison
  src_rules = yield rules_query.fetch_async(limit=_LOCAL_RULE_COPY_LIMIT)
  if len(src_rules) < _LOCAL_RULE_COPY_LIMIT:
    logging.info(
        'Copying %d rules from %s to %s', len(src_rules), src_host_id,
        dest_host_id)
  else:
    logging.warning(
        'Copying maximum of %d rules from %s to %s. More likely exist.',
        len(src_rules), src_host_id, dest_host_id)

  # Copy the local rules to the new host.
  new_rules = []
  for src_rule in src_rules:
    new_rule = model_utils.CopyEntity(
        src_rule, new_parent=src_rule.key.parent(), host_id=dest_host_id,
        user_key=user_key)
    new_rules.append(new_rule)
  logging.info('Copying %s rules to new host', len(new_rules))
  yield ndb.put_multi_async(new_rules)

  # Create the change sets necessary to submit the new rules to Bit9.
  changes = []
  for new_rule in new_rules:
    change = bit9.RuleChangeSet(
        rule_keys=[new_rule.key], change_type=new_rule.policy,
        parent=new_rule.key.parent())
    changes.append(change)
  logging.info('Creating %s RuleChangeSet', len(changes))
  yield ndb.put_multi_async(changes)


@ndb.tasklet
def _PersistBit9Host(computer, occurred_dt):
  """Creates a Bit9Host from the Event protobuf if one does not already exist.

  NOTE: This function could be transactional but, at least for now, host puts in
  multiple requests don't really need to be processed in a fixed order.
  last_event_dt is the only frequently modified property and there's currently
  no need for it to be perfectly accurate.

  Args:
    computer: api.Computer object associated with the event.
    occurred_dt: datetime object corresponding to the time of the event.

  Returns:
    ndb.Future that resolves when the host is updated.
  """
  host_id = str(computer.id)
  policy = computer.policy_id
  policy_key = (
      ndb.Key(bit9.Bit9Policy, str(policy)) if policy is not None else None)
  hostname = utils.ExpandHostname(
      rest_utils.StripDownLevelDomain(computer.name))
  policy_entity = policy_key.get()
  mode = (policy_entity.enforcement_level
          if policy_entity is not None else constants.HOST_MODE.UNKNOWN)

  # Grab the corresponding Bit9Host.
  bit9_host = yield bit9.Bit9Host.get_by_id_async(host_id)

  host_users = list(rest_utils.ExtractHostUsers(computer.users))

  # Perform initialization for users new to this host.
  existing_users = set(bit9_host.users if bit9_host is not None else [])
  new_host_users = set(host_users) - existing_users
  for username in new_host_users:
    # Create User if we haven't seen this user before.
    email = user_map.UsernameToEmail(username)
    user = base.User.GetOrInsert(email_addr=email)

    # Copy the user's local rules over from a pre-existing host.
    yield _CopyLocalRules(user.key, host_id)

  # List of all row action that need to be persisted.
  row_actions = []

  # Doesn't exist? Guess we better fix that.
  if bit9_host is None:
    logging.info('Creating new Bit9Host')
    bit9_host = bit9.Bit9Host(
        id=host_id, hostname=hostname, last_event_dt=occurred_dt,
        policy_key=policy_key, users=host_users)

    row_actions.append(constants.HOST_ACTION.FIRST_SEEN)

  else:
    changed = False
    if not bit9_host.last_event_dt or bit9_host.last_event_dt < occurred_dt:
      bit9_host.last_event_dt = occurred_dt
      changed = True
    if bit9_host.hostname != hostname:
      bit9_host.hostname = hostname
      changed = True
    if bit9_host.policy_key != policy_key:
      bit9_host.policy_key = policy_key
      changed = True
      row_actions.append(constants.HOST_ACTION.MODE_CHANGE)
    if set(bit9_host.users) != set(host_users):
      bit9_host.users = host_users
      changed = True
      row_actions.append(constants.HOST_ACTION.USERS_CHANGE)

    if not changed:
      raise ndb.Return()

  logging.info('Attempting to put Bit9Host...')
  yield bit9_host.put_async()

  for action in row_actions:
    bigquery.HostRow.DeferCreate(
        device_id=host_id,
        timestamp=(
            bit9_host.recorded_dt
            if action == constants.HOST_ACTION.FIRST_SEEN else
            bit9_host.last_event_dt),
        action=action,
        hostname=hostname,
        platform=constants.PLATFORM.WINDOWS,
        users=host_users,
        mode=mode)


def _CheckAndResolveAnomalousBlock(blockable_key, host_id):
  """Checks whether an unfulfilled rule already existed for this blockable.

  If there are unfulfilled rules, triggers an attempt to commit them back to the
  database.

  Args:
    blockable_key: The key of the blockable that was blocked.
    host_id: The host on which the block occurred.

  Returns:
    Whether the block was anomalous (i.e. whether an unfulfilled rule existed
    for the blockable-host pair).
  """
  # Check and handle anomalous block events by detecting unfulfilled rules and,
  # if present, attempting to commit them.
  # pylint: disable=g-explicit-bool-comparison
  unfulfilled_rule_query = bit9.Bit9Rule.query(
      bit9.Bit9Rule.is_committed == True,
      bit9.Bit9Rule.is_fulfilled == False,
      bit9.Bit9Rule.host_id == host_id,
      ancestor=blockable_key
  ).order(bit9.Bit9Rule.updated_dt)
  # pylint: enable=g-explicit-bool-comparison
  unfulfilled_rules = unfulfilled_rule_query.fetch()

  # Installer rules shouldn't be local (e.g. have host_id's) so they shouldn't
  # have been returned by the query. Still, the sanity check couldn't hurt.
  assert all(
      rule.policy in constants.RULE_POLICY.SET_EXECUTION
      for rule in unfulfilled_rules)
  if unfulfilled_rules:
    logging.info(
        'Processing %s unfulfilled rules for %s', len(unfulfilled_rules),
        blockable_key.id())

    # Mark all outstanding unfulfilled rules _except_ the most recent one as
    # fulfilled as we're going to ignore them.
    for rule in unfulfilled_rules[:-1]:
      rule.is_fulfilled = True

    # Mark the most recent unfulfilled rule as uncommitted as we're going to
    # commit it.
    unfulfilled_rules[-1].is_committed = False

    # Create and trigger a change set to commit the most recent rule.
    change = bit9.RuleChangeSet(
        rule_keys=[unfulfilled_rules[-1].key],
        change_type=unfulfilled_rules[-1].policy, parent=blockable_key)

    ndb.put_multi(unfulfilled_rules + [change])

    change_set.DeferCommitBlockableChangeSet(blockable_key)

  return bool(unfulfilled_rules)


def _PersistBit9Events(event, file_catalog, computer, signing_chain):
  """Creates a Bit9Event from the given Event protobuf.

  Args:
    event: The api.Event instance to be synced to Upvote.
    file_catalog: The api.FileCatalog instance associated with this event.
    computer: The api.Computer instance associated with this event.
    signing_chain: List of api.Certificate instances associated with this event.

  Returns:
    An ndb.Future that resolves when all events are created.
  """
  logging.info('Creating new Bit9Event')

  host_id = str(computer.id)
  blockable_key = ndb.Key(bit9.Bit9Binary, file_catalog.sha256)
  host_users = list(rest_utils.ExtractHostUsers(computer.users))
  occurred_dt = event.timestamp

  is_anomalous = _CheckAndResolveAnomalousBlock(blockable_key, host_id)

  new_event = bit9.Bit9Event(
      blockable_key=blockable_key,
      cert_key=_GetCertKey(signing_chain),
      event_type=constants.EVENT_TYPE.BLOCK_BINARY,
      last_blocked_dt=occurred_dt,
      first_blocked_dt=occurred_dt,
      host_id=host_id,
      file_name=event.file_name,
      file_path=event.path_name,
      publisher=file_catalog.publisher,
      version=file_catalog.product_version,
      description=event.description,
      executing_user=rest_utils.ExtractHostUser(event.user_name),
      is_anomalous=is_anomalous,
      bit9_id=event.id)

  bigquery.ExecutionRow.DeferCreate(
      sha256=new_event.blockable_key.id(),
      device_id=host_id,
      timestamp=occurred_dt,
      platform=new_event.GetPlatformName(),
      client=new_event.GetClientName(),
      file_path=new_event.file_path,
      file_name=new_event.file_name,
      executing_user=new_event.executing_user,
      associated_users=host_users,
      decision=new_event.event_type)

  keys_to_insert = new_event.GetKeysToInsert(host_users, host_users)

  futures = [_PersistBit9Event(new_event, key) for key in keys_to_insert]
  return model_utils.GetMultiFuture(futures)


@ndb.transactional_tasklet
def _PersistBit9Event(event, key):
  event_copy = model_utils.CopyEntity(event, new_key=key)
  existing_event = yield key.get_async()
  if existing_event:
    event_copy.Dedupe(existing_event)
  yield event_copy.put_async()
