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

"""Cron handlers responsible for all Bit9 syncing."""

import datetime
import logging
import random
import time

import webapp2
from webapp2_extras import routes

from google.appengine.ext import deferred
from google.appengine.ext import ndb

from common import memcache_decorator
from common import datastore_locks

from upvote.gae.bigquery import tables
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import base
from upvote.gae.datastore.models import bit9
from upvote.gae.datastore.models import cert as cert_models
from upvote.gae.datastore.models import event as event_models
from upvote.gae.datastore.models import host as host_models
from upvote.gae.datastore.models import note as note_models
from upvote.gae.datastore.models import policy as policy_models
from upvote.gae.datastore.models import rule as rule_models
from upvote.gae.datastore.models import user as user_models
from upvote.gae.datastore.models import utils as model_utils
from upvote.gae.lib.analysis import metrics
from upvote.gae.lib.bit9 import api
from upvote.gae.lib.bit9 import change_set
from upvote.gae.lib.bit9 import constants as bit9_constants
from upvote.gae.lib.bit9 import monitoring
from upvote.gae.lib.bit9 import utils as bit9_utils
from upvote.gae.taskqueue import utils as taskqueue_utils
from upvote.gae.utils import handler_utils
from upvote.gae.utils import time_utils
from upvote.gae.utils import user_utils
from upvote.shared import constants


_PULL_MAX_QUEUE_SIZE = 10
_DISPATCH_MAX_QUEUE_SIZE = 10

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

_GET_CERT_ATTEMPTS = 3


# Done for the sake of brevity.
_POLICY = constants.RULE_POLICY


class Error(Exception):
  """Base error."""


class MalformedCertificateError(Error):
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
  event = event_models.Bit9Event.query().order(
      -event_models.Bit9Event.bit9_id).get()
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
    cert = api.Certificate.get(cert_id, bit9_utils.CONTEXT)

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

  raise MalformedCertificateError(message)


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

  events = (
      api.Event.query()
      .filter(api.Event.id > last_synced_id)
      .filter(api.Event.file_catalog_id > 0)
      .filter(BuildEventSubtypeFilter())
      .expand(api.Event.file_catalog_id)
      .expand(api.Event.computer_id)
      .limit(limit)
      .execute(bit9_utils.CONTEXT))

  logging.info('Retrieved %d event(s)', len(events))

  event_cert_tuples = []

  # Maintain a set of (host_id, sha256) tuples for deduping purposes, in case
  # a host gets into a bad state and keeps hammering Bit9 with executions of the
  # same binary.
  deduping_tuples = set()

  # Reverse-sort the events by Bit9 ID. This is done so that if we filter out
  # repeat events during a later iteration, we're still left with the event that
  # has numerically largest ID.
  for event in sorted(events, key=lambda e: e.id, reverse=True):

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

    # If we've already encountered an event with this host_id and sha256, then
    # drop it and move on.
    deduping_tuple = (str(computer.id), file_catalog.sha256)
    if deduping_tuple in deduping_tuples:
      logging.warning('Skipping event %s (Duplicate)', event.id)
      monitoring.events_skipped.Increment()
      continue
    else:
      deduping_tuples.add(deduping_tuple)

    try:
      logging.info('Retrieving signing chain %s', file_catalog.certificate_id)
      signing_chain = _GetSigningChain(file_catalog.certificate_id)

    # If a MalformedCertificateError makes it all the way out here, we've
    # already retried the retrieval a number of times, and have likely hit
    # another fileCatalog containing an "embedded signer". We have to skip this
    # particular event, otherwise event syncing will halt.
    except MalformedCertificateError:
      logging.warning('Skipping event %s (MalformedCertificateError)', event.id)
      monitoring.events_skipped.Increment()
      continue

    # If signing chain retrieval fails for any other reason, just return the
    # events constructed so far.
    except Exception as e:  # pylint: disable=broad-except
      logging.exception('Error encountered while retrieving signing chain')
      logging.warning('Skipping event %s (%s)', event.id, e.__class__.__name__)
      monitoring.events_skipped.Increment()
      continue

    event_cert_tuples.append((event, signing_chain))

  # Flip the event tuples back into order of increasing event ID before
  # returning.
  return sorted(event_cert_tuples, key=lambda t: t[0].id, reverse=False)


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
    logging.info('Unable to acquire datastore lock')


def Dispatch():
  """Dispatches per-host tasks onto the event processing queue."""
  total_dispatch_count = 0
  logging.info('Starting a new dispatch task')

  # Query for all distinct host_id values among the _UnsyncedEvents, in batches,
  # either until we run out, or the task nears its deadline.
  query = _UnsyncedEvent.query(
      projection=[_UnsyncedEvent.host_id], distinct=True)
  for event_page in datastore_utils.Paginate(query, page_size=25):
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
      event_pages = datastore_utils.Paginate(query, page_size=25)
      event_page = next(event_pages, None)
      while time_utils.TimeRemains(start_time, _TASK_DURATION) and event_page:
        for unsynced_event in event_page:
          event = api.Event.from_dict(unsynced_event.event)
          signing_chain = [
              api.Certificate.from_dict(cert)
              for cert in unsynced_event.signing_chain
          ]
          file_catalog = event.get_expand(api.Event.file_catalog_id)
          computer = event.get_expand(api.Event.computer_id)

          # Persist the event data.
          persist_futures = [
              _PersistBit9Certificates(signing_chain),
              _PersistBit9Binary(
                  event, file_catalog, signing_chain,
                  datetime.datetime.utcnow()),
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
    logging.info('Unable to acquire datastore lock')


def _PersistBit9Certificates(signing_chain):
  """Creates Bit9Certificates from the given Event protobuf.

  Args:
    signing_chain: List[api.Certificate] the signing chain of the event.

  Returns:
    An ndb.Future that resolves when all certs are created.
  """
  if not signing_chain:
    return datastore_utils.GetNoOpFuture()

  to_create = []
  for cert in signing_chain:
    thumbprint = cert.thumbprint
    existing_cert = cert_models.Bit9Certificate.get_by_id(thumbprint)
    if existing_cert is None:
      cert = cert_models.Bit9Certificate(
          id=thumbprint,
          id_type=cert.thumbprint_algorithm,
          valid_from_dt=cert.valid_from,
          valid_to_dt=cert.valid_to)

      # Insert a row into the Certificate table. Allow the timestamp to be
      # generated within InsertBigQueryRow(). The Blockable.recorded_dt Property
      # is set to auto_now_add, but this isn't filled in until persist time.
      cert.InsertBigQueryRow(constants.BLOCK_ACTION.FIRST_SEEN)

      to_create.append(cert)

  futures = ndb.put_multi_async(to_create)
  return datastore_utils.GetMultiFuture(futures)


def _GetCertKey(signing_chain):
  fprint = signing_chain[0].thumbprint if signing_chain else None
  return ndb.Key(cert_models.Bit9Certificate, fprint) if fprint else None


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

  # pylint: disable=g-explicit-bool-comparison, singleton-comparison
  installer_query = rule_models.Bit9Rule.query(
      rule_models.Bit9Rule.in_effect == True,
      ndb.OR(
          rule_models.Bit9Rule.policy == _POLICY.FORCE_INSTALLER,
          rule_models.Bit9Rule.policy == _POLICY.FORCE_NOT_INSTALLER),
      ancestor=blockable_key)
  # pylint: enable=g-explicit-bool-comparison, singleton-comparison
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
  new_rule = rule_models.Bit9Rule(
      rule_type=constants.RULE_TYPE.BINARY, in_effect=True, is_committed=True,
      is_fulfilled=True, policy=bit9_policy, parent=blockable_key)
  new_rule.InsertBigQueryRow(
      comment=(
          'Created to mirror the detected forced installer status already '
          'present in Bit9'))
  yield new_rule.put_async()

  raise ndb.Return(True)


@ndb.transactional_tasklet
def _PersistBit9Binary(event, file_catalog, signing_chain, now):
  """Creates or updates a Bit9Binary from the given Event protobuf."""
  changed = False

  # Grab the corresponding Bit9Binary.
  bit9_binary = yield bit9.Bit9Binary.get_by_id_async(file_catalog.sha256)

  detected_installer = bool(
      file_catalog.file_flags &
      bit9_constants.FileFlags.DETECTED_INSTALLER)
  is_installer = (
      bit9_utils.GetEffectiveInstallerState(file_catalog.file_flags))

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

    # Insert a row into the Binary table. Use the timestamp passed in from
    # outside this transaction, otherwise we could end up with duplicate rows in
    # BigQuery in the case of transaction retries. The Blockable.recorded_dt
    # Property is set to auto_now_add, but this isn't filled in until persist
    # time.
    bit9_binary.InsertBigQueryRow(
        constants.BLOCK_ACTION.FIRST_SEEN, timestamp=now)

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

    bit9_binary.InsertBigQueryRow(
        constants.BLOCK_ACTION.STATE_CHANGE, timestamp=event.timestamp)
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
        _POLICY.FORCE_INSTALLER if marked else _POLICY.FORCE_NOT_INSTALLER)
    changed_installer_state = yield _CheckAndResolveInstallerState(
        bit9_binary.key, bit9_policy)
    if changed_installer_state:
      bit9_binary.is_installer = (
          bit9_policy == _POLICY.FORCE_INSTALLER)
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
    note_key = note_models.Note.GenerateKey(full_message, blockable_key)

    if note_key.get() is None:
      logging.info(
          'Persisting new ban Note for %s: %s', file_catalog.sha256,
          ', '.join(ban_strings))
      note = note_models.Note(key=note_key, message=full_message)
      return note.put_async()

  return datastore_utils.GetNoOpFuture()


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
  logging.info(
      'Copying rules for user %s to host %s', user_key.id(), dest_host_id)

  # Query for a host belonging to the user.
  username = user_utils.EmailToUsername(user_key.id())
  query = host_models.Bit9Host.query(host_models.Bit9Host.users == username)
  src_host = yield query.get_async()
  if src_host is None:
    logging.warning('User %s has no hosts to copy from', username)
    raise ndb.Return()
  src_host_id = src_host.key.id()

  # Query for all the Bit9Rules in effect for the given user on the chosen host.
  query = rule_models.Bit9Rule.query(
      rule_models.Bit9Rule.host_id == src_host_id,
      rule_models.Bit9Rule.user_key == user_key,
      rule_models.Bit9Rule.in_effect == True)  # pylint: disable=g-explicit-bool-comparison, singleton-comparison
  src_rules = yield query.fetch_async()
  logging.info(
      'Found a total of %d rule(s) for user %s', len(src_rules), user_key.id())

  # Copy the local rules to the new host.
  logging.info('Copying %d rule(s) to host %s', len(src_rules), dest_host_id)
  new_rules = []
  for src_rule in src_rules:
    new_rule = datastore_utils.CopyEntity(
        src_rule, new_parent=src_rule.key.parent(), host_id=dest_host_id,
        user_key=user_key)
    new_rules.append(new_rule)
    new_rule.InsertBigQueryRow()
  yield ndb.put_multi_async(new_rules)

  # Create the change sets necessary to submit the new rules to Bit9.
  changes = []
  for new_rule in new_rules:
    change = rule_models.RuleChangeSet(
        rule_keys=[new_rule.key], change_type=new_rule.policy,
        parent=new_rule.key.parent())
    changes.append(change)
  logging.info('Creating %d RuleChangeSet(s)', len(changes))
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
      ndb.Key(policy_models.Bit9Policy, str(policy))
      if policy is not None else None)
  hostname = bit9_utils.ExpandHostname(
      bit9_utils.StripDownLevelDomain(computer.name))
  policy_entity = policy_key.get()
  mode = (policy_entity.enforcement_level
          if policy_entity is not None else constants.HOST_MODE.UNKNOWN)

  # Grab the corresponding Bit9Host.
  bit9_host = yield host_models.Bit9Host.get_by_id_async(host_id)

  existing_users = set(bit9_host.users if bit9_host is not None else [])
  extracted_users = list(bit9_utils.ExtractHostUsers(computer.users))

  # Ignore any 'Desktop Window Manager' users, otherwise a user can temporarily
  # become disassociated with their machine. If they vote for something to be
  # locally whitelisted during such a period, they won't get a rule for it.
  incoming_users = set()
  for extracted_user in extracted_users:
    if r'Window Manager\DWM-' in extracted_user:
      logging.warning('Ignoring user "%s"', extracted_user)
    else:
      incoming_users.add(extracted_user)

  # If there are incoming users, either because it was only all 'Desktop Window
  # Manager' entries, or because Bit9 didn't report any users for whatever
  # reason, then just stick with the existing users, otherwise we'll
  # disassociate the machine from the user.
  if not incoming_users:
    incoming_users = existing_users

  # Perform initialization for users new to this host.
  new_users = incoming_users - existing_users
  for new_user in new_users:

    # Create User if we haven't seen this user before.
    email = user_utils.UsernameToEmail(new_user)
    user = user_models.User.GetOrInsert(email_addr=email)

    # Copy the user's local rules over from a pre-existing host.
    yield _CopyLocalRules(user.key, host_id)

  # List of all row action that need to be persisted.
  row_actions = []

  # Doesn't exist? Guess we better fix that.
  if bit9_host is None:
    logging.info('Creating new Bit9Host')
    bit9_host = host_models.Bit9Host(
        id=host_id, hostname=hostname, last_event_dt=occurred_dt,
        policy_key=policy_key, users=sorted(list(incoming_users)))

    row_actions.append(constants.HOST_ACTION.FIRST_SEEN)

  else:
    changed = False

    if not bit9_host.last_event_dt or bit9_host.last_event_dt < occurred_dt:
      bit9_host.last_event_dt = occurred_dt
      changed = True

    if bit9_host.hostname != hostname:
      logging.info(
          'Hostname for %s changed from %s to %s', host_id, bit9_host.hostname,
          hostname)
      bit9_host.hostname = hostname
      changed = True

    if bit9_host.policy_key != policy_key:
      bit9_host.policy_key = policy_key
      changed = True
      row_actions.append(constants.HOST_ACTION.MODE_CHANGE)

    if existing_users != incoming_users:
      existing_users_list = sorted(list(existing_users))
      incoming_users_list = sorted(list(incoming_users))
      logging.info(
          'Users for %s changed from %s to %s', host_id, existing_users_list,
          incoming_users_list)
      bit9_host.users = incoming_users_list
      changed = True
      row_actions.append(constants.HOST_ACTION.USERS_CHANGE)

    if not changed:
      raise ndb.Return()

  logging.info('Attempting to put Bit9Host...')
  yield bit9_host.put_async()

  for action in row_actions:
    tables.HOST.InsertRow(
        device_id=host_id,
        timestamp=(
            bit9_host.recorded_dt
            if action == constants.HOST_ACTION.FIRST_SEEN else
            bit9_host.last_event_dt),
        action=action,
        hostname=hostname,
        platform=constants.PLATFORM.WINDOWS,
        users=sorted(list(incoming_users)),
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
  # pylint: disable=g-explicit-bool-comparison, singleton-comparison
  unfulfilled_rule_query = rule_models.Bit9Rule.query(
      rule_models.Bit9Rule.is_committed == True,
      rule_models.Bit9Rule.is_fulfilled == False,
      rule_models.Bit9Rule.host_id == host_id,
      ancestor=blockable_key
  ).order(rule_models.Bit9Rule.updated_dt)
  # pylint: enable=g-explicit-bool-comparison, singleton-comparison
  unfulfilled_rules = unfulfilled_rule_query.fetch()

  # Installer rules shouldn't be local (e.g. have host_id's) so they shouldn't
  # have been returned by the query. Still, the sanity check couldn't hurt.
  assert all(
      rule.policy in _POLICY.SET_EXECUTION
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
    change = rule_models.RuleChangeSet(
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
  host_users = list(bit9_utils.ExtractHostUsers(computer.users))
  occurred_dt = event.timestamp

  _CheckAndResolveAnomalousBlock(blockable_key, host_id)

  new_event = event_models.Bit9Event(
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
      executing_user=bit9_utils.ExtractHostUser(event.user_name),
      bit9_id=event.id)

  tables.EXECUTION.InsertRow(
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

  keys_to_insert = model_utils.GetEventKeysToInsert(
      new_event, host_users, host_users)

  futures = [_PersistBit9Event(new_event, key) for key in keys_to_insert]
  return datastore_utils.GetMultiFuture(futures)


@ndb.transactional_tasklet
def _PersistBit9Event(event, key):
  event_copy = datastore_utils.CopyEntity(event, new_key=key)
  existing_event = yield key.get_async()
  if existing_event:
    event_copy.Dedupe(existing_event)
  yield event_copy.put_async()


class CommitAllChangeSets(handler_utils.CronJobHandler):
  """Attempt a deferred commit for each Blockable with pending change sets."""

  def get(self):

    start_time = datetime.datetime.utcnow()

    changes = rule_models.RuleChangeSet.query(
        projection=[rule_models.RuleChangeSet.blockable_key],
        distinct=True).fetch()

    # Count the number of distinct SHA256s that have outstanding RuleChangeSets.
    blockable_keys = [change.blockable_key for change in changes]
    blockable_key_count = len(blockable_keys)
    logging.info('Retrieved %d pending change(s)', blockable_key_count)
    monitoring.pending_changes.Set(blockable_key_count)

    # Don't just throw everything into the bit9-commit-change queue, because if
    # anything is still pending when the cron fires again, the queue could start
    # to back up. Allow 3 tasks/sec for the number of seconds remaining (minus a
    # small buffer), evenly spread out over the remaining cron period.
    now = datetime.datetime.utcnow()
    cron_seconds = int(datetime.timedelta(minutes=5).total_seconds())
    elapsed_seconds = int((now - start_time).total_seconds())
    available_seconds = cron_seconds - elapsed_seconds - 10

    # Randomly sample from the outstanding changes in order to avoid
    # head-of-the-line blocking due to unsynced hosts, for example.
    sample_size = min(len(blockable_keys), 3 * available_seconds)
    selected_keys = random.sample(blockable_keys, sample_size)
    logging.info('Deferring %d pending change(s)', len(selected_keys))

    for selected_key in selected_keys:

      # Schedule the task for a random time in the remaining cron period.
      countdown = random.randint(0, available_seconds)
      change_set.DeferCommitBlockableChangeSet(
          selected_key, countdown=countdown)


class UpdateBit9Policies(handler_utils.CronJobHandler):
  """Ensures locally cached policies are up-to-date."""

  def get(self):
    policies_future = policy_models.Bit9Policy.query().fetch_async()

    active_policies = (
        api.Policy.query().filter(api.Policy.total_computers > 0)
        .execute(bit9_utils.CONTEXT))
    local_policies = {
        policy.key.id(): policy for policy in policies_future.get_result()}
    policies_to_update = []
    for policy in active_policies:
      try:
        level = constants.BIT9_ENFORCEMENT_LEVEL.MAP_FROM_INTEGRAL_LEVEL[
            policy.enforcement_level]
      except KeyError:
        logging.warning(
            'Unknown enforcement level "%s". Skipping...',
            policy.enforcement_level)
        continue
      local_policy = local_policies.get(str(policy.id))

      if local_policy is None:
        new_policy = policy_models.Bit9Policy(
            id=str(policy.id), name=policy.name, enforcement_level=level)
        policies_to_update.append(new_policy)
      else:
        dirty = False
        if local_policy.name != policy.name:
          local_policy.name = policy.name
          dirty = True
        if local_policy.enforcement_level != level:
          local_policy.enforcement_level = level
          dirty = True
        if dirty:
          policies_to_update.append(local_policy)

    if policies_to_update:
      logging.info('Updating %s policies', len(policies_to_update))
      ndb.put_multi(policies_to_update)


class CountEventsToPull(handler_utils.CronJobHandler):

  def get(self):
    queue_length = (
        api.Event.query().filter(api.Event.id > GetLastSyncedId())
        .filter(api.Event.file_catalog_id > 0).filter(
            BuildEventSubtypeFilter()).count(bit9_utils.CONTEXT))
    logging.info(
        'There are currently %d events waiting in Bit9', queue_length)
    monitoring.events_to_pull.Set(queue_length)


class PullEvents(handler_utils.CronJobHandler):

  def get(self):
    taskqueue_utils.CappedDefer(
        Pull, _PULL_MAX_QUEUE_SIZE, queue=constants.TASK_QUEUE.BIT9_PULL)


class CountEventsToProcess(handler_utils.CronJobHandler):

  def get(self):
    events_to_process = _UnsyncedEvent.query().count()  # pylint: disable=protected-access
    logging.info('There are currently %d unprocessed events', events_to_process)
    monitoring.events_to_process.Set(events_to_process)


class ProcessEvents(handler_utils.CronJobHandler):

  def get(self):
    taskqueue_utils.CappedDefer(
        Dispatch, _DISPATCH_MAX_QUEUE_SIZE,
        queue=constants.TASK_QUEUE.BIT9_DISPATCH)


ROUTES = routes.PathPrefixRoute('/bit9', [
    webapp2.Route('/commit-pending-change-sets', handler=CommitAllChangeSets),
    webapp2.Route('/update-policies', handler=UpdateBit9Policies),
    webapp2.Route('/count-events-to-pull', handler=CountEventsToPull),
    webapp2.Route('/pull-events', handler=PullEvents),
    webapp2.Route('/count-events-to-process', handler=CountEventsToProcess),
    webapp2.Route('/process-events', handler=ProcessEvents),
])
