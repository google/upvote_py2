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

"""Tests for Bit9 syncing."""

import datetime
import random

import mock

from google.appengine.api import memcache
from google.appengine.ext import ndb

from common import datastore_locks

from absl.testing import absltest
from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils as model_utils
from upvote.gae.datastore.models import base as base_db
from upvote.gae.datastore.models import bigquery as bigquery_db
from upvote.gae.datastore.models import bit9 as bit9_db
from upvote.gae.modules.bit9_api import change_set
from upvote.gae.modules.bit9_api import constants as bit9_constants
from upvote.gae.modules.bit9_api import monitoring
from upvote.gae.modules.bit9_api import sync
from upvote.gae.modules.bit9_api import test_utils as bit9_test_utils
from upvote.gae.modules.bit9_api import utils
from upvote.gae.modules.bit9_api.api import api
from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import settings
from upvote.gae.shared.common import user_map
from upvote.gae.utils import time_utils
from upvote.shared import constants


def _CreateEventTuple(
    computer=None, file_catalog=None, signing_chain=None, **event_kwargs):
  if computer is None:
    computer = bit9_test_utils.CreateComputer()
  if file_catalog is None:
    file_catalog = bit9_test_utils.CreateFileCatalog()
  if signing_chain is None:
    signing_chain = [bit9_test_utils.CreateCertificate()]

  event = bit9_test_utils.CreateEvent(
      computer_id=computer.id, file_catalog_id=file_catalog.id, **event_kwargs)

  event = bit9_test_utils.Expand(event, api.Event.file_catalog_id, file_catalog)
  event = bit9_test_utils.Expand(event, api.Event.computer_id, computer)

  return event, signing_chain


class SyncTestCase(basetest.UpvoteTestCase):

  def _PatchApiRequests(self, *results):
    requests = []
    for batch in results:
      if isinstance(batch, list):
        requests.append([obj._obj_dict for obj in batch])
      else:
        requests.append(batch._obj_dict)
    utils.CONTEXT.ExecuteRequest.side_effect = requests

  def _PatchGetEvents(self, *event_tuple_batches):
    requests = []
    retrieved_certs = set()
    for batch in event_tuple_batches:
      requests.append([event for event, _ in batch])
      for _, certs in batch:
        if certs is None:
          continue
        # Account for the caching on _GetCertificate.
        for cert in certs:
          if cert.id not in retrieved_certs:
            requests.append(cert)
            retrieved_certs.add(cert.id)
    self._PatchApiRequests(*requests)

  def _CreateUnsyncedEvents(self, host_count=1, events_per_host=-1):
    """Creates a bunch of _UnsycnedEvents across a number of Windows hosts.

    Args:
      host_count: The number of hosts to create _UnsyncedEvents for.
      events_per_host: The number of _UnsyncedEvents to create per host. If set
          to -1 (default), creates a random number of _UnsyncedEvents.

    Returns:
      A sorted list of the randomly generated host IDs.
    """
    hosts = [
        bit9_test_utils.CreateComputer(id=host_id)
        for host_id in xrange(host_count)]
    for host in hosts:
      if events_per_host == -1:
        events_per_host = random.randint(1, 5)
      for _ in xrange(events_per_host):
        event, _ = _CreateEventTuple(computer=host)
        sync._UnsyncedEvent.Generate(event, []).put()

    return sorted(host.id for host in hosts)

  def setUp(self, wsgi_app=None):
    super(SyncTestCase, self).setUp(wsgi_app=wsgi_app)
    self.Patch(utils, 'CONTEXT')


class UnsyncedEventTest(basetest.UpvoteTestCase):

  def testPutAndGet(self):
    event, signing_chain = _CreateEventTuple()
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    key = sync._UnsyncedEvent.Generate(event, signing_chain).put()
    entity = key.get()

    self.assertEqual(1, len(entity.signing_chain))
    self.assertEqual(event._obj_dict, entity.event)

    self.assertEqual(file_catalog.sha256, entity.sha256)
    self.assertEqual(event.timestamp, entity.occurred_dt)
    self.assertEqual(event.computer_id, entity.host_id)


class BuildEventSubtypeFilterTest(basetest.UpvoteTestCase):

  def testSuccess(self):
    expected_expression = 'subtype:801|802|837|838|839'
    actual_expression = str(sync.BuildEventSubtypeFilter())
    self.assertEqual(expected_expression, actual_expression)


class GetCertificateTest(basetest.UpvoteTestCase):

  @mock.patch.object(sync.api.Certificate, 'get', side_effect=Exception)
  def testApiError(self, mock_get):

    cert_id = 12345
    memcache_key = sync._CERT_MEMCACHE_KEY % cert_id
    self.assertIsNone(memcache.get(memcache_key))

    with self.assertRaises(Exception):
      sync._GetCertificate(cert_id)

    self.assertIsNone(memcache.get(memcache_key))

  @mock.patch.object(sync.api.Certificate, 'get')
  def testMalformed_SuccessfulRetry(self, mock_get):

    bad_cert = bit9_test_utils.CreateCertificate(
        thumbprint=None, valid_to=None)
    good_cert = bit9_test_utils.CreateCertificate()
    mock_get.side_effect = [bad_cert, good_cert]

    cert_id = 12345
    memcache_key = sync._CERT_MEMCACHE_KEY % cert_id
    self.assertIsNone(memcache.get(memcache_key))

    actual_cert = sync._GetCertificate(cert_id)

    self.assertEqual(good_cert, actual_cert)
    self.assertEqual(2, mock_get.call_count)

    # Verify that the cert is present in memcache.
    cached_cert = memcache.get(memcache_key)
    self.assertEqual(good_cert, cached_cert)

  @mock.patch.object(sync.api.Certificate, 'get')
  def testMalformed_UnsuccessfulRetries(self, mock_get):

    bad_cert = bit9_test_utils.CreateCertificate(
        thumbprint=None, valid_to=None)
    mock_get.side_effect = [bad_cert] * sync._GET_CERT_ATTEMPTS

    cert_id = 12345
    memcache_key = sync._CERT_MEMCACHE_KEY % cert_id
    self.assertIsNone(memcache.get(memcache_key))

    with self.assertRaises(sync.MalformedCertificate):
      sync._GetCertificate(cert_id)

    self.assertIsNone(memcache.get(memcache_key))

  @mock.patch.object(sync.api.Certificate, 'get')
  def testSuccess(self, mock_get):

    expected_cert = bit9_test_utils.CreateCertificate()
    mock_get.return_value = expected_cert

    # The key shouldn't initially be in memcache.
    cert_id = 12345
    memcache_key = sync._CERT_MEMCACHE_KEY % cert_id
    self.assertIsNone(memcache.get(memcache_key))

    # The first call should actually trigger an API query.
    actual_cert = sync._GetCertificate(cert_id)
    self.assertEqual(expected_cert, actual_cert)
    self.assertEqual(1, mock_get.call_count)
    mock_get.reset_mock()

    # Verify that the cert is present in memcache.
    cached_cert = memcache.get(memcache_key)
    self.assertEqual(expected_cert, cached_cert)

    # Additional calls shouldn't hit the API.
    actual_cert = sync._GetCertificate(cert_id)
    self.assertEqual(expected_cert, actual_cert)
    self.assertEqual(0, mock_get.call_count)


class GetSigningChainTest(basetest.UpvoteTestCase):

  @mock.patch.object(sync, '_GetCertificate')
  def testSuccess(self, mock_get_certificate):

    cert_root = bit9_test_utils.CreateCertificate()
    cert_intermediate = bit9_test_utils.CreateCertificate(
        parent_certificate_id=cert_root.id)
    cert_leaf = bit9_test_utils.CreateCertificate(
        parent_certificate_id=cert_intermediate.id)

    expected = [cert_leaf, cert_intermediate, cert_root]
    mock_get_certificate.side_effect = expected

    actual = sync._GetSigningChain(cert_leaf.id)

    self.assertListEqual(expected, actual)


class GetEventsTest(SyncTestCase):

  def setUp(self):
    super(GetEventsTest, self).setUp()
    self.Patch(sync.monitoring, 'events_skipped')

  def testFileCatalogMissing(self):

    # Simulate an event with a missing fileCatalog.
    computer = bit9_test_utils.CreateComputer(id=100)
    signing_chain = [bit9_test_utils.CreateCertificate(id=101)]
    event = bit9_test_utils.CreateEvent(
        id=102, computer_id=100, file_catalog_id=103)
    event = bit9_test_utils.Expand(event, api.Event.computer_id, computer)

    self._PatchGetEvents([(event, signing_chain)])

    results = sync.GetEvents(0)
    self.assertEqual(0, len(results))
    self.assertTrue(sync.monitoring.events_skipped.Increment.called)

  def testFileCatalogMalformed(self):

    # Simulate an event with a malformed fileCatalog (in this case, no SHA256).
    file_catalog = bit9_test_utils.CreateFileCatalog(
        id=100, certificate_id=101, sha256=None)
    computer = bit9_test_utils.CreateComputer(id=102)
    signing_chain = [bit9_test_utils.CreateCertificate(id=101)]
    event = bit9_test_utils.CreateEvent(
        id=103, file_catalog_id=100, computer_id=102)
    event = bit9_test_utils.Expand(
        event, api.Event.file_catalog_id, file_catalog)
    event = bit9_test_utils.Expand(event, api.Event.computer_id, computer)

    self._PatchGetEvents([(event, signing_chain)])

    results = sync.GetEvents(0)
    self.assertEqual(0, len(results))
    self.assertTrue(sync.monitoring.events_skipped.Increment.called)

  def testComputerMissing(self):

    # Simulate an event with a missing computer.
    file_catalog = bit9_test_utils.CreateFileCatalog(
        id=100, certificate_id=101, sha256=None)
    signing_chain = [bit9_test_utils.CreateCertificate(id=101)]
    event = bit9_test_utils.CreateEvent(
        id=102, file_catalog_id=100, computer_id=103)
    event = bit9_test_utils.Expand(
        event, api.Event.file_catalog_id, file_catalog)

    self._PatchGetEvents([(event, signing_chain)])

    results = sync.GetEvents(0)
    self.assertEqual(0, len(results))
    self.assertTrue(sync.monitoring.events_skipped.Increment.called)

  @mock.patch.object(sync, '_GetSigningChain')
  def testSigningChainException(self, mock_get_signing_chain):

    # Create a properly-formed event that will be returned.
    file_catalog_1 = bit9_test_utils.CreateFileCatalog(
        id=100, certificate_id=101)
    computer_1 = bit9_test_utils.CreateComputer(id=102)
    signing_chain_1 = [bit9_test_utils.CreateCertificate(id=101)]
    event_1 = bit9_test_utils.CreateEvent(
        id=103, file_catalog_id=100, computer_id=102)
    event_1 = bit9_test_utils.Expand(
        event_1, api.Event.file_catalog_id, file_catalog_1)
    event_1 = bit9_test_utils.Expand(event_1, api.Event.computer_id, computer_1)

    # Create a second event that will be skipped.
    file_catalog_2 = bit9_test_utils.CreateFileCatalog(
        id=200, certificate_id=201)
    computer_2 = bit9_test_utils.CreateComputer(id=202)
    event_2 = bit9_test_utils.CreateEvent(
        id=203, file_catalog_id=200, computer_id=202)
    event_2 = bit9_test_utils.Expand(
        event_2, api.Event.file_catalog_id, file_catalog_2)
    event_2 = bit9_test_utils.Expand(event_2, api.Event.computer_id, computer_2)

    # Create another properly-formed event that will also be returned.
    file_catalog_3 = bit9_test_utils.CreateFileCatalog(
        id=300, certificate_id=301)
    computer_3 = bit9_test_utils.CreateComputer(id=302)
    signing_chain_3 = [bit9_test_utils.CreateCertificate(id=301)]
    event_3 = bit9_test_utils.CreateEvent(
        id=303, file_catalog_id=300, computer_id=302)
    event_3 = bit9_test_utils.Expand(
        event_3, api.Event.file_catalog_id, file_catalog_3)
    event_3 = bit9_test_utils.Expand(event_3, api.Event.computer_id, computer_3)

    self._PatchGetEvents([
        (event_1, signing_chain_1),
        (event_2, None),
        (event_3, signing_chain_3)])
    mock_get_signing_chain.side_effect = [
        signing_chain_1, sync.MalformedCertificate, signing_chain_3]

    results = sync.GetEvents(0)
    self.assertEqual(2, len(results))
    self.assertTrue(sync.monitoring.events_skipped.Increment.called)

    actual_event_1, actual_signing_chain_1 = results[0]
    self.assertEqual(1, len(actual_signing_chain_1))
    self.assertEqual(103, actual_event_1.id)
    self.assertEqual(101, actual_signing_chain_1[0].id)

    actual_event_3, actual_signing_chain_3 = results[1]
    self.assertEqual(1, len(actual_signing_chain_3))
    self.assertEqual(303, actual_event_3.id)
    self.assertEqual(301, actual_signing_chain_3[0].id)

  @mock.patch.object(sync, '_GetSigningChain')
  def testOtherException(self, mock_get_signing_chain):

    # Create a properly-formed event that will be returned.
    file_catalog_1 = bit9_test_utils.CreateFileCatalog(
        id=100, certificate_id=101)
    computer_1 = bit9_test_utils.CreateComputer(id=102)
    signing_chain_1 = [bit9_test_utils.CreateCertificate(id=101)]
    event_1 = bit9_test_utils.CreateEvent(
        id=103, file_catalog_id=100, computer_id=102)
    event_1 = bit9_test_utils.Expand(
        event_1, api.Event.file_catalog_id, file_catalog_1)
    event_1 = bit9_test_utils.Expand(event_1, api.Event.computer_id, computer_1)

    # Create a second event that will hit an exception.
    file_catalog_2 = bit9_test_utils.CreateFileCatalog(
        id=200, certificate_id=201)
    computer_2 = bit9_test_utils.CreateComputer(id=202)
    event_2 = bit9_test_utils.CreateEvent(
        id=203, file_catalog_id=200, computer_id=202)
    event_2 = bit9_test_utils.Expand(
        event_2, api.Event.file_catalog_id, file_catalog_2)
    event_2 = bit9_test_utils.Expand(event_2, api.Event.computer_id, computer_2)

    # Create another properly-formed event won't be returned.
    file_catalog_3 = bit9_test_utils.CreateFileCatalog(
        id=300, certificate_id=301)
    computer_3 = bit9_test_utils.CreateComputer(id=302)
    signing_chain_3 = [bit9_test_utils.CreateCertificate(id=301)]
    event_3 = bit9_test_utils.CreateEvent(
        id=303, file_catalog_id=300, computer_id=302)
    event_3 = bit9_test_utils.Expand(
        event_3, api.Event.file_catalog_id, file_catalog_3)
    event_3 = bit9_test_utils.Expand(event_3, api.Event.computer_id, computer_3)

    self._PatchGetEvents([
        (event_1, signing_chain_1),
        (event_2, None),
        (event_3, signing_chain_3)])
    mock_get_signing_chain.side_effect = [
        signing_chain_1, Exception, signing_chain_3]

    results = sync.GetEvents(0)
    self.assertEqual(1, len(results))
    self.assertFalse(sync.monitoring.events_skipped.Increment.called)

    actual_event_1, actual_signing_chain_1 = results[0]
    self.assertEqual(1, len(actual_signing_chain_1))
    self.assertEqual(103, actual_event_1.id)
    self.assertEqual(101, actual_signing_chain_1[0].id)

  def testSuccess(self):

    # Create two properly-formed events to be returned.
    file_catalog_1 = bit9_test_utils.CreateFileCatalog(
        id=100, certificate_id=101)
    computer_1 = bit9_test_utils.CreateComputer(id=102)
    signing_chain_1 = [bit9_test_utils.CreateCertificate(id=101)]
    event_1 = bit9_test_utils.CreateEvent(
        id=103, file_catalog_id=100, computer_id=102)
    event_1 = bit9_test_utils.Expand(
        event_1, api.Event.file_catalog_id, file_catalog_1)
    event_1 = bit9_test_utils.Expand(event_1, api.Event.computer_id, computer_1)

    file_catalog_2 = bit9_test_utils.CreateFileCatalog(
        id=200, certificate_id=201)
    computer_2 = bit9_test_utils.CreateComputer(id=202)
    signing_chain_2 = [bit9_test_utils.CreateCertificate(id=201)]
    event_2 = bit9_test_utils.CreateEvent(
        id=203, file_catalog_id=200, computer_id=202)
    event_2 = bit9_test_utils.Expand(
        event_2, api.Event.file_catalog_id, file_catalog_2)
    event_2 = bit9_test_utils.Expand(event_2, api.Event.computer_id, computer_2)

    self._PatchGetEvents(
        [(event_1, signing_chain_1), (event_2, signing_chain_2)])

    results = sync.GetEvents(0)
    self.assertEqual(2, len(results))
    self.assertListEqual([103, 203], [e.id for e, _ in results])
    self.assertListEqual(
        [[101], [201]], [[c.id for c in sc] for _, sc in results])


class PullTest(SyncTestCase):

  def setUp(self):
    super(PullTest, self).setUp()
    self.mock_events_pulled = self.Patch(monitoring, 'events_pulled')

  def testOrder(self):
    event1, signing_chain1 = _CreateEventTuple(id=100)
    event2, signing_chain2 = _CreateEventTuple(id=200)

    self._PatchGetEvents([(event1, signing_chain1)], [(event2, signing_chain2)])
    self.Patch(time_utils, 'TimeRemains', side_effect=[True, True, False])

    sync.Pull(batch_size=1)

    events = (sync._UnsyncedEvent.query()
              .order(sync._UnsyncedEvent.bit9_id)
              .fetch())
    self.assertEqual(2, len(events))
    self.assertEqual(event1._obj_dict, events[0].event)
    self.assertEqual(event2._obj_dict, events[1].event)
    self.assertEqual(2, self.mock_events_pulled.IncrementBy.call_count)

  def testMultiple(self):

    batch_count = 3
    events_per_batch = 5
    batches = []

    for batch_num in xrange(batch_count):
      batches.append([
          _CreateEventTuple(id=batch_num * events_per_batch + event_num)
          for event_num in xrange(events_per_batch)])

    self._PatchGetEvents(*batches)
    self.Patch(time_utils, 'TimeRemains', side_effect=[True, True, True, False])

    sync.Pull(batch_size=events_per_batch)

    self.assertEntityCount(sync._UnsyncedEvent, batch_count * events_per_batch)
    self.assertEqual(
        batch_count, self.mock_events_pulled.IncrementBy.call_count)

    self.assertTaskCount(constants.TASK_QUEUE.BIT9_PULL, 0)

  def testBadEvent(self):
    event, signing_chain = _CreateEventTuple(id=100)
    # Create an event with no expands.
    broken_event = bit9_test_utils.CreateEvent()

    self._PatchGetEvents([(event, signing_chain), (broken_event, None)])
    self.Patch(time_utils, 'TimeRemains', side_effect=[True, True, False])

    sync.Pull()

    events = (sync._UnsyncedEvent.query()
              .order(sync._UnsyncedEvent.bit9_id)
              .fetch())
    self.assertEqual(1, len(events))
    self.assertEqual(event._obj_dict, events[0].event)


class DispatchTest(SyncTestCase):

  def testDispatch(self):
    expected_host_count = 5
    expected_host_ids = self._CreateUnsyncedEvents(
        host_count=expected_host_count)

    sync.Dispatch()

    # Verify that a deferred task was created for each unique host_id.
    self.assertTaskCount(
        constants.TASK_QUEUE.BIT9_PROCESS, expected_host_count)
    tasks = self.UnpackTaskQueue(queue_name=constants.TASK_QUEUE.BIT9_PROCESS)
    actual_host_ids = [task[1][0] for task in tasks]
    self.assertEqual(expected_host_ids, actual_host_ids)


class ProcessTest(SyncTestCase):

  def setUp(self):
    super(ProcessTest, self).setUp()

    self.mock_lock = mock.Mock()
    self.mock_lock.__enter__ = mock.Mock(return_value=self.mock_lock)
    self.mock_lock.__exit__ = mock.Mock()
    self.Patch(
        sync.datastore_locks, 'DatastoreLock', return_value=self.mock_lock)

    self.mock_events_processed = self.Patch(monitoring, 'events_processed')

    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  def testPersistsCertificateRow(self):
    event, signing_chain = _CreateEventTuple()
    sync._UnsyncedEvent.Generate(event, signing_chain).put()

    # Patch out the all methods except _PersistBit9Certificates.
    methods = [
        '_PersistBit9Binary', '_PersistBanNote',
        '_PersistBit9Host', '_PersistBit9Events']
    for method in methods:
      self.Patch(sync, method, return_value=model_utils.GetNoOpFuture())

    sync.Process(event.computer_id)

    # Should be 1 Task for the CertificateRow caused by the event.
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
    self.RunDeferredTasks(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertEntityCount(bigquery_db.CertificateRow, 1)

  def testPersistsExecutionRow(self):
    event_count = 3
    host_id = self._CreateUnsyncedEvents(events_per_host=event_count)[0]

    # Patch out the all methods except _PersistBit9Events.
    methods = [
        '_PersistBit9Certificates', '_PersistBit9Binary',
        '_PersistBanNote', '_PersistBit9Host']
    for method in methods:
      self.Patch(sync, method, return_value=model_utils.GetNoOpFuture())

    sync.Process(host_id)

    # Should be 3 ExecutionRows since 3 Unsynced Events were created.
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, event_count)
    self.RunDeferredTasks(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertEntityCount(bigquery_db.ExecutionRow, event_count)

  def testEventsExist(self):
    event_count = 5
    host_id = self._CreateUnsyncedEvents(events_per_host=event_count)[0]

    # Patch out the various _Persist methods since they're tested below.
    methods = [
        '_PersistBit9Certificates', '_PersistBit9Binary', '_PersistBanNote',
        '_PersistBit9Host', '_PersistBit9Events'
    ]
    for method in methods:
      self.Patch(sync, method, return_value=model_utils.GetNoOpFuture())

    sync.Process(host_id)

    # Verify all usage of the DatastoreLock.
    self.assertTrue(self.mock_lock.__enter__.called)
    self.assertTrue(self.mock_lock.__exit__.called)

    # Verify everything was persisted.
    self.assertEqual(event_count, sync._PersistBit9Certificates.call_count)
    self.assertEqual(event_count, sync._PersistBit9Binary.call_count)
    self.assertEqual(event_count, sync._PersistBanNote.call_count)
    self.assertEqual(event_count, sync._PersistBit9Host.call_count)
    self.assertEqual(event_count, sync._PersistBit9Events.call_count)

    self.assertEqual(event_count,
                     self.mock_events_processed.Increment.call_count)

  def testNoEventsExist(self):
    # Patch out the various _Persist methods since they're tested below.
    methods = [
        '_PersistBit9Certificates', '_PersistBit9Binary', '_PersistBanNote',
        '_PersistBit9Host', '_PersistBit9Events'
    ]
    for method in methods:
      self.Patch(sync, method, return_value=model_utils.GetNoOpFuture())

    sync.Process(12345)

    # Verify all usage of the DatastoreLock.
    self.assertTrue(self.mock_lock.__enter__.called)
    self.assertTrue(self.mock_lock.__exit__.called)

    # Verify everything was persisted.
    self.assertEqual(0, sync._PersistBit9Certificates.call_count)
    self.assertEqual(0, sync._PersistBit9Binary.call_count)
    self.assertEqual(0, sync._PersistBanNote.call_count)
    self.assertEqual(0, sync._PersistBit9Host.call_count)
    self.assertEqual(0, sync._PersistBit9Events.call_count)

    self.assertEqual(0, self.mock_events_processed.Increment.call_count)

  def testAcquireLockError(self):
    self.mock_lock.__enter__.side_effect = datastore_locks.AcquireLockError()

    sync.Process(12345)

    # Verify all usage of the DatastoreLock.
    self.assertTrue(self.mock_lock.__enter__.called)
    self.assertFalse(self.mock_lock.__exit__.called)

    # Verify no work was done.
    self.assertTaskCount(constants.TASK_QUEUE.BIT9_PROCESS, 0)
    self.assertFalse(self.mock_events_processed.Increment.called)

class PersistBit9CertificatesTest(basetest.UpvoteTestCase):

  def testNoSigningChain(self):
    self.assertEntityCount(bit9_db.Bit9Certificate, 0)
    sync._PersistBit9Certificates([]).wait()
    self.assertEntityCount(bit9_db.Bit9Certificate, 0)

  def testDupeCerts(self):

    # Create some cert entities, and a matching protobuf signing chain.
    bit9_certs = test_utils.CreateBit9Certificates(3)
    thumbprints = [c.key.id() for c in bit9_certs]
    signing_chain = [
        bit9_test_utils.CreateCertificate(thumbprint=t) for t in thumbprints]
    bit9_test_utils.LinkSigningChain(*signing_chain)

    self.assertEntityCount(bit9_db.Bit9Certificate, 3)
    sync._PersistBit9Certificates(signing_chain).wait()
    self.assertEntityCount(bit9_db.Bit9Certificate, 3)

  def testNewCerts(self):

    # Create some certs, and an unrelated signing chain.
    test_utils.CreateBit9Certificates(3)
    signing_chain = [
        bit9_test_utils.CreateCertificate(thumbprint=test_utils.RandomSHA1())
        for _ in xrange(4)]
    bit9_test_utils.LinkSigningChain(*signing_chain)

    self.assertEntityCount(bit9_db.Bit9Certificate, 3)
    sync._PersistBit9Certificates(signing_chain).wait()
    self.assertEntityCount(bit9_db.Bit9Certificate, 7)


class GetCertKeyTest(basetest.UpvoteTestCase):

  def testWithSigningChain(self):
    signing_chain = [
        bit9_test_utils.CreateCertificate(thumbprint=test_utils.RandomSHA1())
        for _ in xrange(4)]
    bit9_test_utils.LinkSigningChain(*signing_chain)

    expected_key = ndb.Key(
        bit9_db.Bit9Certificate, signing_chain[0].thumbprint)
    self.assertEqual(expected_key, sync._GetCertKey(signing_chain))

  def testWithoutSigningChain(self):
    self.assertIsNone(sync._GetCertKey([]))


class PersistBit9BinaryTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(PersistBit9BinaryTest, self).setUp()

    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  def testNewBit9Binary(self):
    event, signing_chain = _CreateEventTuple(
        subtype=bit9_constants.SUBTYPE.BANNED)
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    self.assertEntityCount(bit9_db.Bit9Binary, 0)

    changed = sync._PersistBit9Binary(
        event, file_catalog, signing_chain).get_result()

    self.assertTrue(changed)
    self.assertEntityCount(bit9_db.Bit9Binary, 1)

    # Should be 2: 1 for new Binary, 1 For the BANNED State.
    self.DrainTaskQueue(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertEntityCount(bigquery_db.BinaryRow, 2)

  def testNewBit9Binary_ForcedInstaller(self):
    self.PatchSetting('ENABLE_BINARY_ANALYSIS_PRECACHING', True)

    event, signing_chain = _CreateEventTuple(
        file_catalog=bit9_test_utils.CreateFileCatalog(
            file_flags=bit9_constants.FileFlags.MARKED_INSTALLER))
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    self.assertEntityCount(bit9_db.Bit9Binary, 0)
    self.assertEntityCount(bit9_db.Bit9Rule, 0)

    changed = sync._PersistBit9Binary(
        event, file_catalog, signing_chain).get_result()

    self.assertTrue(changed)
    self.assertEntityCount(bit9_db.Bit9Binary, 1)
    self.assertEntityCount(bit9_db.Bit9Rule, 1)

    binary = bit9_db.Bit9Binary.query().get()
    self.assertTrue(binary.is_installer)
    self.assertFalse(binary.detected_installer)

    rule = bit9_db.Bit9Rule.query().get()
    self.assertTrue(constants.RULE_POLICY.FORCE_INSTALLER, rule.policy)

    self.assertTaskCount(constants.TASK_QUEUE.METRICS, 1)

    # Should be 1 for the new Binary
    self.DrainTaskQueue(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertEntityCount(bigquery_db.BinaryRow, 1)

  def testFileCatalogIdChanged(self):

    bit9_binary = test_utils.CreateBit9Binary(file_catalog_id='12345')
    sha256 = bit9_binary.key.id()

    event, signing_chain = _CreateEventTuple(
        file_catalog=bit9_test_utils.CreateFileCatalog(
            id='67890',
            sha256=sha256))
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    changed = sync._PersistBit9Binary(
        event, file_catalog, signing_chain).get_result()

    self.assertTrue(changed)
    bit9_binary = bit9_db.Bit9Binary.get_by_id(sha256)
    self.assertEqual('67890', bit9_binary.file_catalog_id)

    # Should be Empty: No new Binary or BANNED State.
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)

  def testFileCatalogIdInitiallyMissing(self):
    bit9_binary = test_utils.CreateBit9Binary(file_catalog_id=None)
    sha256 = bit9_binary.key.id()

    event, signing_chain = _CreateEventTuple(
        file_catalog=bit9_test_utils.CreateFileCatalog(
            id='12345',
            sha256=sha256))
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    changed = sync._PersistBit9Binary(
        event, file_catalog, signing_chain).get_result()

    self.assertTrue(changed)
    bit9_binary = bit9_db.Bit9Binary.get_by_id(sha256)
    self.assertEqual('12345', bit9_binary.file_catalog_id)

    # Should be Empty: No new Binary or BANNED State.
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)

  def testStateChangedToBanned(self):
    bit9_binary = test_utils.CreateBit9Binary(state=constants.STATE.UNTRUSTED)
    sha256 = bit9_binary.key.id()

    event, signing_chain = _CreateEventTuple(
        subtype=bit9_constants.SUBTYPE.BANNED,
        file_catalog=bit9_test_utils.CreateFileCatalog(
            id='12345',
            sha256=sha256))
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    changed = sync._PersistBit9Binary(
        event, file_catalog, signing_chain).get_result()

    self.assertTrue(changed)
    bit9_binary = bit9_db.Bit9Binary.get_by_id(sha256)
    self.assertEqual(constants.STATE.BANNED, bit9_binary.state)

    # Should be 1 for the BANNED State.
    self.DrainTaskQueue(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertEntityCount(bigquery_db.BinaryRow, 1)

  def testForcedInstaller_PreexistingRule_SamePolicy(self):
    bit9_binary = test_utils.CreateBit9Binary(detected_installer=False)
    test_utils.CreateBit9Rule(
        bit9_binary.key,
        is_committed=True,
        policy=constants.RULE_POLICY.FORCE_NOT_INSTALLER)
    bit9_binary.put()
    self.assertFalse(bit9_binary.is_installer)

    event, signing_chain = _CreateEventTuple(
        file_catalog=bit9_test_utils.CreateFileCatalog(
            id=bit9_binary.file_catalog_id,
            sha256=bit9_binary.key.id(),
            file_flags=bit9_constants.FileFlags.MARKED_NOT_INSTALLER))
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    changed = sync._PersistBit9Binary(
        event, file_catalog, signing_chain).get_result()

    self.assertFalse(changed)
    self.assertFalse(bit9_binary.key.get().is_installer)

    # Empty because Binary is not new and State is not BANNED.
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)

  def testForcedInstaller_PreexistingRule_ConflictingPolicy(self):
    bit9_binary = test_utils.CreateBit9Binary(
        detected_installer=False, is_installer=False)
    test_utils.CreateBit9Rule(
        bit9_binary.key,
        is_committed=True,
        policy=constants.RULE_POLICY.FORCE_NOT_INSTALLER)

    event, signing_chain = _CreateEventTuple(
        file_catalog=bit9_test_utils.CreateFileCatalog(
            id=bit9_binary.file_catalog_id,
            sha256=bit9_binary.key.id(),
            file_flags=bit9_constants.FileFlags.MARKED_INSTALLER))
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    changed = sync._PersistBit9Binary(
        event, file_catalog, signing_chain).get_result()

    self.assertTrue(changed)
    self.assertTrue(bit9_binary.key.get().is_installer)

    # Empty because Binary is not new and State is not BANNED.
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)

  def testNoChanges(self):
    bit9_binary = test_utils.CreateBit9Binary(detected_installer=False)

    event, signing_chain = _CreateEventTuple(
        file_catalog=bit9_test_utils.CreateFileCatalog(
            id=bit9_binary.file_catalog_id,
            sha256=bit9_binary.key.id(),
            file_flags=0x0))
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    changed = sync._PersistBit9Binary(
        event, file_catalog, signing_chain).get_result()

    self.assertFalse(changed)
    # Empty because Binary is not new and State is not BANNED.
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)


class PersistBanNoteTest(basetest.UpvoteTestCase):

  def testNoBans(self):
    bit9_binary = test_utils.CreateBit9Binary()

    file_catalog = bit9_test_utils.CreateFileCatalog(
        id=bit9_binary.file_catalog_id,
        sha256=bit9_binary.key.id(),
        certificate_state=bit9_constants.APPROVAL_STATE.APPROVED,
        file_state=bit9_constants.APPROVAL_STATE.APPROVED,
        publisher_state=bit9_constants.APPROVAL_STATE.APPROVED)

    self.assertEntityCount(base_db.Note, 0)
    sync._PersistBanNote(file_catalog).wait()
    self.assertEntityCount(base_db.Note, 0)

  def testNewBan(self):
    bit9_binary = test_utils.CreateBit9Binary()

    # Create FileCatalog with at least one that's BANNED.
    file_catalog = bit9_test_utils.CreateFileCatalog(
        id=bit9_binary.file_catalog_id,
        sha256=bit9_binary.key.id(),
        certificate_state=bit9_constants.APPROVAL_STATE.BANNED,
        file_state=bit9_constants.APPROVAL_STATE.APPROVED,
        publisher_state=bit9_constants.APPROVAL_STATE.APPROVED)

    self.assertEntityCount(base_db.Note, 0)
    sync._PersistBanNote(file_catalog).wait()
    self.assertEntityCount(base_db.Note, 1)

  def testDupeBan(self):
    bit9_binary = test_utils.CreateBit9Binary()

    file_catalog = bit9_test_utils.CreateFileCatalog(
        id=bit9_binary.file_catalog_id,
        sha256=bit9_binary.key.id(),
        certificate_state=bit9_constants.APPROVAL_STATE.BANNED,
        file_state=bit9_constants.APPROVAL_STATE.APPROVED,
        publisher_state=bit9_constants.APPROVAL_STATE.APPROVED)

    self.assertEntityCount(base_db.Note, 0)
    sync._PersistBanNote(file_catalog).wait()
    self.assertEntityCount(base_db.Note, 1)
    sync._PersistBanNote(file_catalog).wait()
    self.assertEntityCount(base_db.Note, 1)


class CopyLocalRulesTest(basetest.UpvoteTestCase):

  def testSuccess(self):
    old_user = test_utils.CreateUser(email=user_map.UsernameToEmail('foo'))
    new_user = test_utils.CreateUser(email=user_map.UsernameToEmail('bar'))
    policy_key = ndb.Key(bit9_db.Bit9Policy, '22222')

    host1 = test_utils.CreateBit9Host(
        id='12345', users=[old_user.nickname], policy_key=policy_key)
    test_utils.CreateBit9Host(
        id='67890', users=[new_user.nickname], policy_key=policy_key)

    blockable1 = test_utils.CreateBit9Binary()
    test_utils.CreateBit9Rule(
        blockable1.key, host_id=host1.key.id(), user_key=old_user.key)
    blockable2 = test_utils.CreateBit9Binary()
    test_utils.CreateBit9Rule(
        blockable2.key, host_id=host1.key.id(), user_key=old_user.key)

    computer = bit9_test_utils.CreateComputer(
        id=67890,
        policy_id=22222,
        users='{0}\\{1},{0}\\{2}'.format(
            settings.AD_DOMAIN, old_user.nickname, new_user.nickname))
    occurred_dt = datetime.datetime.utcnow()

    sync._PersistBit9Host(computer, occurred_dt).wait()

    self.assertEntityCount(bit9_db.Bit9Rule, 4)  # 2 New + 2 Old
    self.assertEntityCount(bit9_db.RuleChangeSet, 2)
    rules_for_host1 = bit9_db.Bit9Rule.query(
        bit9_db.Bit9Rule.host_id == host1.key.id()).fetch()
    self.assertEqual(2, len(rules_for_host1))
    self.assertSameElements(
        [blockable1.key, blockable2.key],
        [rule.key.parent() for rule in rules_for_host1])
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
    self.DrainTaskQueue(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertEntityCount(bigquery_db.HostRow, 1)

  def testNoPreviousHosts(self):
    old_user = test_utils.CreateUser(email=user_map.UsernameToEmail('foo'))
    new_user = test_utils.CreateUser(email=user_map.UsernameToEmail('bar'))

    test_utils.CreateBit9Host(
        id='12345', users=[old_user.nickname],
        policy_key=ndb.Key(bit9_db.Bit9Policy, '22222'))

    computer = bit9_test_utils.CreateComputer(
        id=12345,
        policy_id=22222,
        users='{0}\\{1},{0}\\{2}'.format(
            settings.AD_DOMAIN, old_user.nickname, new_user.nickname))
    occurred_dt = datetime.datetime.utcnow()

    sync._PersistBit9Host(computer, occurred_dt).wait()

    self.assertEntityCount(bit9_db.Bit9Rule, 0)
    self.assertEntityCount(bit9_db.RuleChangeSet, 0)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
    self.DrainTaskQueue(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertEntityCount(bigquery_db.HostRow, 1)

  def testMaximumRules(self):
    user_1 = test_utils.CreateUser(email=user_map.UsernameToEmail('one'))
    user_2 = test_utils.CreateUser(email=user_map.UsernameToEmail('two'))
    policy_key = ndb.Key(bit9_db.Bit9Policy, '22222')

    host_1 = test_utils.CreateBit9Host(
        id='12345', users=[user_1.nickname], policy_key=policy_key)
    host_2 = test_utils.CreateBit9Host(
        id='67890', users=[user_2.nickname], policy_key=policy_key)

    blockable_1 = test_utils.CreateBit9Binary()
    test_utils.CreateBit9Rules(
        blockable_1.key, sync._LOCAL_RULE_COPY_LIMIT + 1,
        host_id=host_1.key.id(), user_key=user_1.key)

    computer = bit9_test_utils.CreateComputer(
        id=67890,
        policy_id=22222,
        users='{0}\\{1},{0}\\{2}'.format(
            settings.AD_DOMAIN, user_1.nickname, user_2.nickname))
    occurred_dt = datetime.datetime.utcnow()

    sync._PersistBit9Host(computer, occurred_dt).wait()

    expected_rule_count_1 = sync._LOCAL_RULE_COPY_LIMIT + 1
    expected_rule_count_2 = sync._LOCAL_RULE_COPY_LIMIT
    actual_rule_count_1 = bit9_db.Bit9Rule.query(
        bit9_db.Bit9Rule.host_id == host_1.key.id()).count()
    actual_rule_count_2 = bit9_db.Bit9Rule.query(
        bit9_db.Bit9Rule.host_id == host_2.key.id()).count()

    self.assertEntityCount(
        bit9_db.Bit9Rule, expected_rule_count_1 + expected_rule_count_2)
    self.assertEqual(expected_rule_count_1, actual_rule_count_1)
    self.assertEqual(expected_rule_count_2, actual_rule_count_2)
    self.assertEntityCount(bit9_db.RuleChangeSet, sync._LOCAL_RULE_COPY_LIMIT)

    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
    self.DrainTaskQueue(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertEntityCount(bigquery_db.HostRow, 1)


class PersistBit9HostTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(PersistBit9HostTest, self).setUp()

    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  def testNewHost(self):
    users = test_utils.RandomStrings(2)
    host = bit9_test_utils.CreateComputer(
        users='{0}\\{1},{0}\\{2}'.format(settings.AD_DOMAIN, *users))
    occurred_dt = datetime.datetime.utcnow()

    self.assertEntityCount(bit9_db.Bit9Host, 0)
    self.assertEntityCount(bigquery_db.HostRow, 0)
    self.assertEntityCount(bigquery_db.UserRow, 0)

    sync._PersistBit9Host(host, occurred_dt).wait()

    self.assertEntityCount(bit9_db.Bit9Host, 1)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 3)
    self.DrainTaskQueue(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertEntityCount(bigquery_db.HostRow, 1)
    self.assertEntityCount(bigquery_db.UserRow, 2)

  def testUpdateLastEventDt(self):
    now_dt = datetime.datetime.utcnow()
    earlier_dt = now_dt - datetime.timedelta(days=7)
    users = test_utils.RandomStrings(2)
    policy_key = ndb.Key(bit9_db.Bit9Policy, '100')

    test_utils.CreateBit9Host(
        id='12345', last_event_dt=earlier_dt, users=users,
        policy_key=policy_key)

    host = bit9_test_utils.CreateComputer(
        id=12345,
        policy_id=100,
        users='{0}\\{1},{0}\\{2}'.format(settings.AD_DOMAIN, *users))

    sync._PersistBit9Host(host, now_dt).wait()

    bit9_host = bit9_db.Bit9Host.get_by_id('12345')
    self.assertEqual(now_dt, bit9_host.last_event_dt)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)

  def testUpdateHostname(self):
    users = test_utils.RandomStrings(2)
    policy_key = ndb.Key(bit9_db.Bit9Policy, '100')

    test_utils.CreateBit9Host(
        id='12345', hostname=utils.ExpandHostname('hostname1'), users=users,
        policy_key=policy_key)

    host = bit9_test_utils.CreateComputer(
        id=12345,
        name='hostname2',
        policy_id=100,
        users='{0}\\{1},{0}\\{2}'.format(settings.AD_DOMAIN, *users))
    occurred_dt = datetime.datetime.utcnow()

    sync._PersistBit9Host(host, occurred_dt).wait()

    bit9_host = bit9_db.Bit9Host.get_by_id('12345')
    self.assertEqual(utils.ExpandHostname('hostname2'), bit9_host.hostname)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)

  def testUpdatePolicyKey(self):
    users = test_utils.RandomStrings(2)
    old_policy_key = ndb.Key(bit9_db.Bit9Policy, '22222')

    test_utils.CreateBit9Host(
        id='11111', policy_key=old_policy_key, users=users)

    host = bit9_test_utils.CreateComputer(
        id=11111,
        policy_id=33333,
        users='{0}\\{1},{0}\\{2}'.format(settings.AD_DOMAIN, *users))
    occurred_dt = datetime.datetime.utcnow()

    sync._PersistBit9Host(host, occurred_dt).wait()

    bit9_host = bit9_db.Bit9Host.get_by_id('11111')
    new_policy_key = ndb.Key(bit9_db.Bit9Policy, '33333')
    self.assertEqual(new_policy_key, bit9_host.policy_key)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
    self.RunDeferredTasks(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertEntityCount(bigquery_db.HostRow, 1)

  def testUpdateHostUsers(self):
    old_users = test_utils.RandomStrings(2)
    new_users = test_utils.RandomStrings(2)
    policy_key = ndb.Key(bit9_db.Bit9Policy, '22222')

    test_utils.CreateBit9Host(
        id='12345', users=old_users, policy_key=policy_key)

    host = bit9_test_utils.CreateComputer(
        id=12345,
        policy_id=22222,
        users='{0}\\{1},{0}\\{2}'.format(settings.AD_DOMAIN, *new_users))
    occurred_dt = datetime.datetime.utcnow()

    sync._PersistBit9Host(host, occurred_dt).wait()

    bit9_db.Bit9Host.get_by_id('12345')
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 3)
    self.DrainTaskQueue(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertEntityCount(bigquery_db.HostRow, 1)
    self.assertEntityCount(bigquery_db.UserRow, 2)


class CheckAndResolveAnomalousBlockTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(CheckAndResolveAnomalousBlockTest, self).setUp()
    self.mock_defer = self.Patch(change_set, 'DeferCommitBlockableChangeSet')

  def testFulfilled(self):
    bit9_binary = test_utils.CreateBit9Binary()
    test_utils.CreateBit9Rules(
        bit9_binary.key,
        5,
        is_committed=True,
        is_fulfilled=True,
        host_id='12345')

    result = sync._CheckAndResolveAnomalousBlock(bit9_binary.key, '12345')
    self.assertFalse(result)
    self.assertFalse(self.mock_defer.called)

  def testUnfulfilled(self):
    self.Patch(change_set, 'DeferCommitBlockableChangeSet')

    bit9_binary = test_utils.CreateBit9Binary()
    now = datetime.datetime.utcnow()

    # Create some conflicting Bit9Rules.
    rule1 = test_utils.CreateBit9Rule(
        bit9_binary.key,
        is_committed=True,
        is_fulfilled=False,
        host_id='12345',
        updated_dt=now - datetime.timedelta(hours=3),
        policy=constants.RULE_POLICY.WHITELIST)
    rule2 = test_utils.CreateBit9Rule(
        bit9_binary.key,
        is_committed=True,
        is_fulfilled=False,
        host_id='12345',
        updated_dt=now - datetime.timedelta(hours=2),
        policy=constants.RULE_POLICY.WHITELIST)
    rule3 = test_utils.CreateBit9Rule(
        bit9_binary.key,
        is_committed=True,
        is_fulfilled=False,
        host_id='12345',
        updated_dt=now - datetime.timedelta(hours=1),
        policy=constants.RULE_POLICY.BLACKLIST)

    # Verify a RuleChangeSet doesn't yet exist.
    self.assertEntityCount(bit9_db.RuleChangeSet, 0)

    result = sync._CheckAndResolveAnomalousBlock(bit9_binary.key, '12345')
    self.assertTrue(result)

    # Verify that all Rules except the most recent have been fulfilled.
    self.assertTrue(rule1.key.get().is_fulfilled)
    self.assertTrue(rule2.key.get().is_fulfilled)
    self.assertFalse(rule3.key.get().is_fulfilled)

    # Verify that the most recent Rule is uncommitted.
    self.assertTrue(rule1.key.get().is_committed)
    self.assertTrue(rule2.key.get().is_committed)
    self.assertFalse(rule3.key.get().is_committed)

    # Verify the creation of a RuleChangeSet.
    self.assertEntityCount(bit9_db.RuleChangeSet, 1)

    # Verify the deferred commit to Bit9.
    self.assertTrue(change_set.DeferCommitBlockableChangeSet.called)


class PersistBit9EventsTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(PersistBit9EventsTest, self).setUp()
    self.Patch(sync, '_CheckAndResolveAnomalousBlock', return_value=False)

  def testSuccess_ExecutingUser(self):
    event, signing_chain = _CreateEventTuple()
    file_catalog = event.get_expand(api.Event.file_catalog_id)
    computer = event.get_expand(api.Event.computer_id)

    self.assertEntityCount(bit9_db.Bit9Event, 0)
    sync._PersistBit9Events(
        event, file_catalog, computer, signing_chain).wait()
    self.assertEntityCount(bit9_db.Bit9Event, 1)

  def testSuccess_LocalAdmin(self):
    computer = bit9_test_utils.CreateComputer(
        users='{0}\\foobar,{0}\\bazqux'.format(settings.AD_DOMAIN))
    event, signing_chain = _CreateEventTuple(
        user_name=constants.LOCAL_ADMIN.WINDOWS, computer=computer)
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    self.assertEntityCount(bit9_db.Bit9Event, 0)
    sync._PersistBit9Events(
        event, file_catalog, computer, signing_chain).wait()
    self.assertEntityCount(bit9_db.Bit9Event, 2)


if __name__ == '__main__':
  absltest.main()
