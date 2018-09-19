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

"""Tests for bit9_api cron jobs."""

import datetime
import httplib
import itertools
import random

import mock
import webapp2

from google.appengine.api import memcache

from google.appengine.ext import ndb

from common import datastore_locks

from absl.testing import absltest
from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils as model_utils

from upvote.gae.datastore.models import base as base_models
from upvote.gae.datastore.models import bit9 as bit9_models
from upvote.gae.datastore.models import user as user_models

from upvote.gae.lib.bit9 import api
from upvote.gae.lib.bit9 import change_set
from upvote.gae.lib.bit9 import constants as bit9_constants
from upvote.gae.lib.bit9 import monitoring
from upvote.gae.lib.bit9 import test_utils as bit9_test_utils
from upvote.gae.lib.bit9 import utils as bit9_utils
from upvote.gae.lib.testing import basetest
from upvote.gae.modules.bit9_api import cron
from upvote.gae.shared.common import settings
from upvote.gae.shared.common import user_map
from upvote.gae.utils import time_utils
from upvote.shared import constants


def _CreateEventsAndCerts(
    count=1, event_kwargs=None, file_catalog_kwargs=None, computer_kwargs=None):

  event_kwargs = event_kwargs or {}
  file_catalog_kwargs = file_catalog_kwargs or {}
  computer_kwargs = computer_kwargs or {}

  # Create a generator for each type of ID, with each range starting where the
  # previous one left off.
  id_gens = itertools.izip(
      xrange(100 + (count * 0), 100 + (count * 1)),
      xrange(100 + (count * 1), 100 + (count * 2)),
      xrange(100 + (count * 2), 100 + (count * 3)),
      xrange(100 + (count * 3), 100 + (count * 4)))

  events = []
  certs = []

  for event_id, file_catalog_id, computer_id, certificate_id in id_gens:

    # Construct the Certificate.
    cert = bit9_test_utils.CreateCertificate(id=certificate_id)

    # Construct the Computer.
    computer_id = computer_kwargs.get('id', computer_id)
    computer_defaults = {'id': computer_id}
    computer_defaults.update(computer_kwargs.copy())
    computer = bit9_test_utils.CreateComputer(**computer_defaults)

    # Construct the FileCatalog.
    file_catalog_id = file_catalog_kwargs.get('id', file_catalog_id)
    file_catalog_defaults = {
        'id': file_catalog_id,
        'certificate_id': certificate_id}
    file_catalog_defaults.update(file_catalog_kwargs.copy())
    file_catalog = bit9_test_utils.CreateFileCatalog(**file_catalog_defaults)

    # Construct the Event.
    event_defaults = {
        'id': event_id,
        'file_catalog_id': file_catalog_id,
        'computer_id': computer_id}
    event_defaults.update(event_kwargs.copy())
    event = bit9_test_utils.CreateEvent(**event_defaults)
    event = bit9_test_utils.Expand(
        event, api.Event.file_catalog_id, file_catalog)
    event = bit9_test_utils.Expand(event, api.Event.computer_id, computer)

    events.append(event)
    # Stuff the certs in backwards due to the reverse sorting in GetEvents().
    certs.insert(0, cert)

  return events, certs


def _CreateEventAndCert(
    file_catalog_kwargs=None, computer_kwargs=None, event_kwargs=None):

  events, certs = _CreateEventsAndCerts(
      count=1, file_catalog_kwargs=file_catalog_kwargs,
      computer_kwargs=computer_kwargs, event_kwargs=event_kwargs)

  return (events[0], certs[0])


def _CreateUnsyncedEvents(host_count=1, events_per_host=-1):
  """Creates a bunch of _UnsycnedEvents across a number of Windows hosts.

  Args:
    host_count: The number of hosts to create _UnsyncedEvents for.
    events_per_host: The number of _UnsyncedEvents to create per host. If set
        to -1 (default), creates a random number of _UnsyncedEvents.

  Returns:
    A sorted list of the randomly generated host IDs.
  """
  computer_ids = range(host_count)

  for computer_id in computer_ids:
    event_count = (
        random.randint(1, 5) if events_per_host == -1 else events_per_host)
    for _ in xrange(event_count):
      event, _ = _CreateEventAndCert(computer_kwargs={'id': computer_id})
      cron._UnsyncedEvent.Generate(event, []).put()

  return computer_ids


class SyncTestCase(basetest.UpvoteTestCase):

  def _AppendMockApiResults(self, *args):
    for arg in args:

      # Mock out the api.Event.query() in GetEvents().
      if isinstance(arg, list):
        new_side_effect = [item._obj_dict for item in arg]
        self._api_side_effects.append(new_side_effect)

      # Mock out the api.Certificate.get() in _GetCertificate().
      elif isinstance(arg, api.Certificate):
        # Don't mock the same Certificate more than once because of the caching.
        if arg.id not in self._api_cert_ids:
          self._api_cert_ids.add(arg.id)
          self._api_side_effects.append(arg._obj_dict)

      bit9_utils.CONTEXT.ExecuteRequest.side_effect = self._api_side_effects

  def setUp(self, wsgi_app=None):
    super(SyncTestCase, self).setUp(wsgi_app=wsgi_app)
    self.Patch(bit9_utils, 'CONTEXT')
    self._api_side_effects = []
    self._api_cert_ids = set()


class UnsyncedEventTest(basetest.UpvoteTestCase):

  def testPutAndGet(self):
    event, cert = _CreateEventAndCert()
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    key = cron._UnsyncedEvent.Generate(event, [cert]).put()
    entity = key.get()

    self.assertEqual(1, len(entity.signing_chain))
    self.assertEqual(event._obj_dict, entity.event)

    self.assertEqual(file_catalog.sha256, entity.sha256)
    self.assertEqual(event.timestamp, entity.occurred_dt)
    self.assertEqual(event.computer_id, entity.host_id)


class BuildEventSubtypeFilterTest(basetest.UpvoteTestCase):

  def testSuccess(self):
    expected_expression = 'subtype:801|802|837|838|839'
    actual_expression = str(cron.BuildEventSubtypeFilter())
    self.assertEqual(expected_expression, actual_expression)


class GetCertificateTest(basetest.UpvoteTestCase):

  @mock.patch.object(cron.api.Certificate, 'get', side_effect=Exception)
  def testApiError(self, mock_get):

    cert_id = 12345
    memcache_key = cron._CERT_MEMCACHE_KEY % cert_id
    self.assertIsNone(memcache.get(memcache_key))

    with self.assertRaises(Exception):
      cron._GetCertificate(cert_id)

    self.assertIsNone(memcache.get(memcache_key))

  @mock.patch.object(cron.api.Certificate, 'get')
  def testMalformed_SuccessfulRetry(self, mock_get):

    bad_cert = bit9_test_utils.CreateCertificate(
        thumbprint=None, valid_to=None)
    good_cert = bit9_test_utils.CreateCertificate()
    mock_get.side_effect = [bad_cert, good_cert]

    cert_id = 12345
    memcache_key = cron._CERT_MEMCACHE_KEY % cert_id
    self.assertIsNone(memcache.get(memcache_key))

    actual_cert = cron._GetCertificate(cert_id)

    self.assertEqual(good_cert, actual_cert)
    self.assertEqual(2, mock_get.call_count)

    # Verify that the cert is present in memcache.
    cached_cert = memcache.get(memcache_key)
    self.assertEqual(good_cert, cached_cert)

  @mock.patch.object(cron.api.Certificate, 'get')
  def testMalformed_UnsuccessfulRetries(self, mock_get):

    bad_cert = bit9_test_utils.CreateCertificate(
        thumbprint=None, valid_to=None)
    mock_get.side_effect = [bad_cert] * cron._GET_CERT_ATTEMPTS

    cert_id = 12345
    memcache_key = cron._CERT_MEMCACHE_KEY % cert_id
    self.assertIsNone(memcache.get(memcache_key))

    with self.assertRaises(cron.MalformedCertificate):
      cron._GetCertificate(cert_id)

    self.assertIsNone(memcache.get(memcache_key))

  @mock.patch.object(cron.api.Certificate, 'get')
  def testSuccess(self, mock_get):

    expected_cert = bit9_test_utils.CreateCertificate()
    mock_get.return_value = expected_cert

    # The key shouldn't initially be in memcache.
    cert_id = 12345
    memcache_key = cron._CERT_MEMCACHE_KEY % cert_id
    self.assertIsNone(memcache.get(memcache_key))

    # The first call should actually trigger an API query.
    actual_cert = cron._GetCertificate(cert_id)
    self.assertEqual(expected_cert, actual_cert)
    self.assertEqual(1, mock_get.call_count)
    mock_get.reset_mock()

    # Verify that the cert is present in memcache.
    cached_cert = memcache.get(memcache_key)
    self.assertEqual(expected_cert, cached_cert)

    # Additional calls shouldn't hit the API.
    actual_cert = cron._GetCertificate(cert_id)
    self.assertEqual(expected_cert, actual_cert)
    self.assertEqual(0, mock_get.call_count)


class GetSigningChainTest(basetest.UpvoteTestCase):

  @mock.patch.object(cron, '_GetCertificate')
  def testSuccess(self, mock_get_certificate):

    cert_root = bit9_test_utils.CreateCertificate()
    cert_intermediate = bit9_test_utils.CreateCertificate(
        parent_certificate_id=cert_root.id)
    cert_leaf = bit9_test_utils.CreateCertificate(
        parent_certificate_id=cert_intermediate.id)

    expected = [cert_leaf, cert_intermediate, cert_root]
    mock_get_certificate.side_effect = expected

    actual = cron._GetSigningChain(cert_leaf.id)

    self.assertListEqual(expected, actual)


class GetEventsTest(SyncTestCase):

  def setUp(self):
    super(GetEventsTest, self).setUp()
    self.Patch(cron.monitoring, 'events_skipped')

  def testFileCatalogMissing(self):

    # Simulate an event with a missing fileCatalog.
    computer = bit9_test_utils.CreateComputer(id=100)
    signing_chain = [bit9_test_utils.CreateCertificate(id=101)]
    event = bit9_test_utils.CreateEvent(
        id=102, computer_id=100, file_catalog_id=103)
    event = bit9_test_utils.Expand(event, api.Event.computer_id, computer)

    self._AppendMockApiResults(event, signing_chain)

    results = cron.GetEvents(0)
    self.assertEqual(0, len(results))
    self.assertTrue(cron.monitoring.events_skipped.Increment.called)

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

    self._AppendMockApiResults(event, signing_chain)

    results = cron.GetEvents(0)
    self.assertEqual(0, len(results))
    self.assertTrue(cron.monitoring.events_skipped.Increment.called)

  def testComputerMissing(self):

    # Simulate an event with a missing computer.
    file_catalog = bit9_test_utils.CreateFileCatalog(
        id=100, certificate_id=101, sha256=None)
    signing_chain = [bit9_test_utils.CreateCertificate(id=101)]
    event = bit9_test_utils.CreateEvent(
        id=102, file_catalog_id=100, computer_id=103)
    event = bit9_test_utils.Expand(
        event, api.Event.file_catalog_id, file_catalog)

    self._AppendMockApiResults(event, signing_chain)

    results = cron.GetEvents(0)
    self.assertEqual(0, len(results))
    self.assertTrue(cron.monitoring.events_skipped.Increment.called)

  @mock.patch.object(cron.monitoring, 'events_skipped')
  def testDuplicateEventsFromHost(self, mock_events_skipped):

    events, certs = _CreateEventsAndCerts(
        count=100, computer_kwargs={'id': 999},
        file_catalog_kwargs={'sha256': test_utils.RandomSHA256()})

    expected_event_id = events[-1].id
    expected_cert_id = certs[0].id

    self._AppendMockApiResults(events, *certs)

    results = cron.GetEvents(0)
    self.assertEqual(1, len(results))
    self.assertEqual(expected_event_id, results[0][0].id)
    self.assertEqual(expected_cert_id, results[0][1][0].id)

    self.assertEqual(99, mock_events_skipped.Increment.call_count)

  @mock.patch.object(cron, '_GetSigningChain')
  def testSigningChainException(self, mock_get_signing_chain):

    # Create a properly-formed event that will be returned.
    file_catalog_1 = bit9_test_utils.CreateFileCatalog(
        id=100, certificate_id=101)
    computer_1 = bit9_test_utils.CreateComputer(id=102)
    cert_1 = bit9_test_utils.CreateCertificate(id=101)
    signing_chain_1 = [cert_1]
    event_1 = bit9_test_utils.CreateEvent(
        id=103, file_catalog_id=100, computer_id=102)
    event_1 = bit9_test_utils.Expand(
        event_1, api.Event.file_catalog_id, file_catalog_1)
    event_1 = bit9_test_utils.Expand(
        event_1, api.Event.computer_id, computer_1)

    # Create a second event that will be skipped.
    file_catalog_2 = bit9_test_utils.CreateFileCatalog(
        id=200, certificate_id=201)
    computer_2 = bit9_test_utils.CreateComputer(id=202)
    event_2 = bit9_test_utils.CreateEvent(
        id=203, file_catalog_id=200, computer_id=202)
    event_2 = bit9_test_utils.Expand(
        event_2, api.Event.file_catalog_id, file_catalog_2)
    event_2 = bit9_test_utils.Expand(
        event_2, api.Event.computer_id, computer_2)

    # Create another properly-formed event that will also be returned.
    file_catalog_3 = bit9_test_utils.CreateFileCatalog(
        id=300, certificate_id=301)
    computer_3 = bit9_test_utils.CreateComputer(id=302)
    cert_3 = bit9_test_utils.CreateCertificate(id=301)
    signing_chain_3 = [cert_3]
    event_3 = bit9_test_utils.CreateEvent(
        id=303, file_catalog_id=300, computer_id=302)
    event_3 = bit9_test_utils.Expand(
        event_3, api.Event.file_catalog_id, file_catalog_3)
    event_3 = bit9_test_utils.Expand(
        event_3, api.Event.computer_id, computer_3)

    self._AppendMockApiResults([event_1, event_2, event_3], cert_3, cert_1)
    mock_get_signing_chain.side_effect = [
        signing_chain_3, cron.MalformedCertificate, signing_chain_1]

    results = cron.GetEvents(0)
    self.assertEqual(2, len(results))
    self.assertTrue(cron.monitoring.events_skipped.Increment.called)

    actual_event_1, actual_signing_chain_1 = results[0]
    self.assertEqual(1, len(actual_signing_chain_1))
    self.assertEqual(103, actual_event_1.id)
    self.assertEqual(101, actual_signing_chain_1[0].id)

    actual_event_3, actual_signing_chain_3 = results[1]
    self.assertEqual(1, len(actual_signing_chain_3))
    self.assertEqual(303, actual_event_3.id)
    self.assertEqual(301, actual_signing_chain_3[0].id)

  @mock.patch.object(cron, '_GetSigningChain')
  def testOtherException(self, mock_get_signing_chain):

    # Create a properly-formed event that will be returned.
    file_catalog_1 = bit9_test_utils.CreateFileCatalog(
        id=100, certificate_id=101)
    computer_1 = bit9_test_utils.CreateComputer(id=102)
    cert_1 = bit9_test_utils.CreateCertificate(id=101)
    signing_chain_1 = [cert_1]
    event_1 = bit9_test_utils.CreateEvent(
        id=103, file_catalog_id=100, computer_id=102)
    event_1 = bit9_test_utils.Expand(
        event_1, api.Event.file_catalog_id, file_catalog_1)
    event_1 = bit9_test_utils.Expand(
        event_1, api.Event.computer_id, computer_1)

    # Create a second event that will hit an exception.
    file_catalog_2 = bit9_test_utils.CreateFileCatalog(
        id=200, certificate_id=201)
    computer_2 = bit9_test_utils.CreateComputer(id=202)
    event_2 = bit9_test_utils.CreateEvent(
        id=203, file_catalog_id=200, computer_id=202)
    event_2 = bit9_test_utils.Expand(
        event_2, api.Event.file_catalog_id, file_catalog_2)
    event_2 = bit9_test_utils.Expand(
        event_2, api.Event.computer_id, computer_2)

    # Create another properly-formed event won't be returned.
    file_catalog_3 = bit9_test_utils.CreateFileCatalog(
        id=300, certificate_id=301)
    computer_3 = bit9_test_utils.CreateComputer(id=302)
    cert_3 = bit9_test_utils.CreateCertificate(id=301)
    signing_chain_3 = [cert_3]
    event_3 = bit9_test_utils.CreateEvent(
        id=303, file_catalog_id=300, computer_id=302)
    event_3 = bit9_test_utils.Expand(
        event_3, api.Event.file_catalog_id, file_catalog_3)
    event_3 = bit9_test_utils.Expand(
        event_3, api.Event.computer_id, computer_3)

    self._AppendMockApiResults([event_1, event_2, event_3], cert_3, cert_1)
    mock_get_signing_chain.side_effect = [
        signing_chain_3, Exception, signing_chain_1]

    results = cron.GetEvents(0)
    self.assertEqual(2, len(results))
    self.assertTrue(cron.monitoring.events_skipped.Increment.called)

    actual_event_1, actual_signing_chain_1 = results[0]
    self.assertEqual(1, len(actual_signing_chain_1))
    self.assertEqual(103, actual_event_1.id)
    self.assertEqual(101, actual_signing_chain_1[0].id)

    actual_event_3, actual_signing_chain_3 = results[1]
    self.assertEqual(1, len(actual_signing_chain_3))
    self.assertEqual(303, actual_event_3.id)
    self.assertEqual(301, actual_signing_chain_3[0].id)

  def testSuccess(self):

    # Create two properly-formed events to be returned.
    file_catalog_1 = bit9_test_utils.CreateFileCatalog(
        id=100, certificate_id=101)
    computer_1 = bit9_test_utils.CreateComputer(id=102)
    cert_1 = bit9_test_utils.CreateCertificate(id=101)
    event_1 = bit9_test_utils.CreateEvent(
        id=103, file_catalog_id=100, computer_id=102)
    event_1 = bit9_test_utils.Expand(
        event_1, api.Event.file_catalog_id, file_catalog_1)
    event_1 = bit9_test_utils.Expand(
        event_1, api.Event.computer_id, computer_1)

    file_catalog_2 = bit9_test_utils.CreateFileCatalog(
        id=200, certificate_id=201)
    computer_2 = bit9_test_utils.CreateComputer(id=202)
    cert_2 = bit9_test_utils.CreateCertificate(id=201)
    event_2 = bit9_test_utils.CreateEvent(
        id=203, file_catalog_id=200, computer_id=202)
    event_2 = bit9_test_utils.Expand(
        event_2, api.Event.file_catalog_id, file_catalog_2)
    event_2 = bit9_test_utils.Expand(
        event_2, api.Event.computer_id, computer_2)

    self._AppendMockApiResults([event_1, event_2], cert_2, cert_1)

    results = cron.GetEvents(0)
    self.assertEqual(2, len(results))
    self.assertListEqual([103, 203], [e.id for e, _ in results])
    self.assertListEqual(
        [[101], [201]], [[c.id for c in sc] for _, sc in results])


class PullTest(SyncTestCase):

  def setUp(self):
    super(PullTest, self).setUp()
    self.mock_events_pulled = self.Patch(monitoring, 'events_pulled')

  def testOrder(self):
    event_1, cert_1 = _CreateEventAndCert()
    event_2, cert_2 = _CreateEventAndCert()

    self._AppendMockApiResults([event_1], cert_1, [event_2], cert_2)
    self.Patch(time_utils, 'TimeRemains', side_effect=[True, True, False])

    cron.Pull(batch_size=1)

    events = (cron._UnsyncedEvent.query()
              .order(cron._UnsyncedEvent.bit9_id)
              .fetch())
    self.assertEqual(2, len(events))
    self.assertEqual(event_1._obj_dict, events[0].event)
    self.assertEqual(event_2._obj_dict, events[1].event)
    self.assertEqual(2, self.mock_events_pulled.IncrementBy.call_count)

  def testMultiple(self):

    batch_count = 3
    events_per_batch = 5

    for _ in xrange(batch_count):
      events, certs = _CreateEventsAndCerts(count=events_per_batch)
      self._AppendMockApiResults(events, *certs)

    self.Patch(time_utils, 'TimeRemains', side_effect=[True, True, True, False])

    cron.Pull(batch_size=events_per_batch)

    self.assertEntityCount(cron._UnsyncedEvent, batch_count * events_per_batch)
    self.assertEqual(
        batch_count, self.mock_events_pulled.IncrementBy.call_count)

    self.assertTaskCount(constants.TASK_QUEUE.BIT9_PULL, 0)

  def testBadEvent(self):
    event, cert = _CreateEventAndCert()
    # Create an event with no expands.
    broken_event = bit9_test_utils.CreateEvent()

    self._AppendMockApiResults([event, broken_event], cert)
    self.Patch(time_utils, 'TimeRemains', side_effect=[True, True, False])

    cron.Pull()

    events = (cron._UnsyncedEvent.query()
              .order(cron._UnsyncedEvent.bit9_id)
              .fetch())
    self.assertEqual(1, len(events))
    self.assertEqual(event._obj_dict, events[0].event)


class DispatchTest(SyncTestCase):

  def testDispatch(self):
    expected_host_count = 5
    expected_host_ids = _CreateUnsyncedEvents(host_count=expected_host_count)

    cron.Dispatch()

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
        cron.datastore_locks, 'DatastoreLock', return_value=self.mock_lock)

    self.mock_events_processed = self.Patch(monitoring, 'events_processed')

    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  def testInsertsCertificateRow(self):
    event, cert = _CreateEventAndCert()
    cron._UnsyncedEvent.Generate(event, [cert]).put()

    # Patch out the all methods except _PersistBit9Certificates.
    methods = [
        '_PersistBit9Binary', '_PersistBanNote',
        '_PersistBit9Host', '_PersistBit9Events']
    for method in methods:
      self.Patch(cron, method, return_value=model_utils.GetNoOpFuture())

    cron.Process(event.computer_id)

    # Should be 1 Task for the CertificateRow caused by the event.
    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.CERTIFICATE])

  def testInsertsExecutionRow(self):
    event_count = 3
    host_id = _CreateUnsyncedEvents(events_per_host=event_count)[0]

    # Patch out the all methods except _PersistBit9Events.
    methods = [
        '_PersistBit9Certificates', '_PersistBit9Binary',
        '_PersistBanNote', '_PersistBit9Host']
    for method in methods:
      self.Patch(cron, method, return_value=model_utils.GetNoOpFuture())

    cron.Process(host_id)

    # Should be 3 ExecutionRows since 3 Unsynced Events were created.
    self.assertBigQueryInsertions(
        [constants.BIGQUERY_TABLE.EXECUTION] * event_count)

  def testEventsExist(self):
    event_count = 5
    host_id = _CreateUnsyncedEvents(events_per_host=event_count)[0]

    # Patch out the various _Persist methods since they're tested below.
    methods = [
        '_PersistBit9Certificates', '_PersistBit9Binary', '_PersistBanNote',
        '_PersistBit9Host', '_PersistBit9Events'
    ]
    for method in methods:
      self.Patch(cron, method, return_value=model_utils.GetNoOpFuture())

    cron.Process(host_id)

    # Verify all usage of the DatastoreLock.
    self.assertTrue(self.mock_lock.__enter__.called)
    self.assertTrue(self.mock_lock.__exit__.called)

    # Verify everything was persisted.
    self.assertEqual(event_count, cron._PersistBit9Certificates.call_count)
    self.assertEqual(event_count, cron._PersistBit9Binary.call_count)
    self.assertEqual(event_count, cron._PersistBanNote.call_count)
    self.assertEqual(event_count, cron._PersistBit9Host.call_count)
    self.assertEqual(event_count, cron._PersistBit9Events.call_count)

    self.assertEqual(
        event_count, self.mock_events_processed.Increment.call_count)

  def testNoEventsExist(self):
    # Patch out the various _Persist methods since they're tested below.
    methods = [
        '_PersistBit9Certificates', '_PersistBit9Binary', '_PersistBanNote',
        '_PersistBit9Host', '_PersistBit9Events'
    ]
    for method in methods:
      self.Patch(cron, method, return_value=model_utils.GetNoOpFuture())

    cron.Process(12345)

    # Verify all usage of the DatastoreLock.
    self.assertTrue(self.mock_lock.__enter__.called)
    self.assertTrue(self.mock_lock.__exit__.called)

    # Verify everything was persisted.
    self.assertEqual(0, cron._PersistBit9Certificates.call_count)
    self.assertEqual(0, cron._PersistBit9Binary.call_count)
    self.assertEqual(0, cron._PersistBanNote.call_count)
    self.assertEqual(0, cron._PersistBit9Host.call_count)
    self.assertEqual(0, cron._PersistBit9Events.call_count)

    self.assertEqual(0, self.mock_events_processed.Increment.call_count)

  def testAcquireLockError(self):
    self.mock_lock.__enter__.side_effect = datastore_locks.AcquireLockError()

    cron.Process(12345)

    # Verify all usage of the DatastoreLock.
    self.assertTrue(self.mock_lock.__enter__.called)
    self.assertFalse(self.mock_lock.__exit__.called)

    # Verify no work was done.
    self.assertTaskCount(constants.TASK_QUEUE.BIT9_PROCESS, 0)
    self.assertFalse(self.mock_events_processed.Increment.called)

class PersistBit9CertificatesTest(basetest.UpvoteTestCase):

  def testNoSigningChain(self):
    self.assertEntityCount(bit9_models.Bit9Certificate, 0)
    cron._PersistBit9Certificates([]).wait()
    self.assertEntityCount(bit9_models.Bit9Certificate, 0)

  def testDupeCerts(self):

    # Create some cert entities, and a matching protobuf signing chain.
    bit9_certs = test_utils.CreateBit9Certificates(3)
    thumbprints = [c.key.id() for c in bit9_certs]
    signing_chain = [
        bit9_test_utils.CreateCertificate(thumbprint=t) for t in thumbprints]
    bit9_test_utils.LinkSigningChain(*signing_chain)

    self.assertEntityCount(bit9_models.Bit9Certificate, 3)
    cron._PersistBit9Certificates(signing_chain).wait()
    self.assertEntityCount(bit9_models.Bit9Certificate, 3)

  def testNewCerts(self):

    # Create some certs, and an unrelated signing chain.
    test_utils.CreateBit9Certificates(3)
    signing_chain = [
        bit9_test_utils.CreateCertificate(thumbprint=test_utils.RandomSHA1())
        for _ in xrange(4)]
    bit9_test_utils.LinkSigningChain(*signing_chain)

    self.assertEntityCount(bit9_models.Bit9Certificate, 3)
    cron._PersistBit9Certificates(signing_chain).wait()
    self.assertEntityCount(bit9_models.Bit9Certificate, 7)

    self.assertBigQueryInsertions(
        [constants.BIGQUERY_TABLE.CERTIFICATE] * len(signing_chain))


class GetCertKeyTest(basetest.UpvoteTestCase):

  def testWithSigningChain(self):
    signing_chain = [
        bit9_test_utils.CreateCertificate(thumbprint=test_utils.RandomSHA1())
        for _ in xrange(4)]
    bit9_test_utils.LinkSigningChain(*signing_chain)

    expected_key = ndb.Key(
        bit9_models.Bit9Certificate, signing_chain[0].thumbprint)
    self.assertEqual(expected_key, cron._GetCertKey(signing_chain))

  def testWithoutSigningChain(self):
    self.assertIsNone(cron._GetCertKey([]))


class PersistBit9BinaryTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(PersistBit9BinaryTest, self).setUp()
    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  def testNewBit9Binary(self):
    event, cert = _CreateEventAndCert(
        event_kwargs={'subtype': bit9_constants.SUBTYPE.BANNED})
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    self.assertEntityCount(bit9_models.Bit9Binary, 0)

    changed = cron._PersistBit9Binary(
        event, file_catalog, [cert], datetime.datetime.utcnow()).get_result()

    self.assertTrue(changed)
    self.assertEntityCount(bit9_models.Bit9Binary, 1)

    # Should be 2: 1 for new Binary, 1 For the BANNED State.
    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.BINARY] * 2)

  def testNewBit9Binary_ForcedInstaller(self):
    self.PatchSetting('ENABLE_BINARY_ANALYSIS_PRECACHING', True)

    file_catalog_kwargs = {
        'file_flags': bit9_constants.FileFlags.MARKED_INSTALLER}
    event, cert = _CreateEventAndCert(
        file_catalog_kwargs=file_catalog_kwargs)
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    self.assertEntityCount(bit9_models.Bit9Binary, 0)
    self.assertEntityCount(bit9_models.Bit9Rule, 0)

    changed = cron._PersistBit9Binary(
        event, file_catalog, [cert], datetime.datetime.utcnow()).get_result()

    self.assertTrue(changed)
    self.assertEntityCount(bit9_models.Bit9Binary, 1)
    self.assertEntityCount(bit9_models.Bit9Rule, 1)

    binary = bit9_models.Bit9Binary.query().get()
    self.assertTrue(binary.is_installer)
    self.assertFalse(binary.detected_installer)

    rule = bit9_models.Bit9Rule.query().get()
    self.assertTrue(constants.RULE_POLICY.FORCE_INSTALLER, rule.policy)

    self.assertTaskCount(constants.TASK_QUEUE.METRICS, 1)

    self.assertBigQueryInsertions(
        [constants.BIGQUERY_TABLE.BINARY, constants.BIGQUERY_TABLE.RULE])

  def testFileCatalogIdChanged(self):

    bit9_binary = test_utils.CreateBit9Binary(file_catalog_id='12345')
    sha256 = bit9_binary.key.id()

    file_catalog_kwargs = {'id': '67890', 'sha256': sha256}
    event, cert = _CreateEventAndCert(file_catalog_kwargs=file_catalog_kwargs)
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    changed = cron._PersistBit9Binary(
        event, file_catalog, [cert], datetime.datetime.utcnow()).get_result()

    self.assertTrue(changed)
    bit9_binary = bit9_models.Bit9Binary.get_by_id(sha256)
    self.assertEqual('67890', bit9_binary.file_catalog_id)

    # Should be Empty: No new Binary or BANNED State.
    self.assertNoBigQueryInsertions()

  def testFileCatalogIdInitiallyMissing(self):
    bit9_binary = test_utils.CreateBit9Binary(file_catalog_id=None)
    sha256 = bit9_binary.key.id()

    file_catalog_kwargs = {'id': '12345', 'sha256': sha256}
    event, cert = _CreateEventAndCert(file_catalog_kwargs=file_catalog_kwargs)
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    changed = cron._PersistBit9Binary(
        event, file_catalog, [cert], datetime.datetime.utcnow()).get_result()

    self.assertTrue(changed)
    bit9_binary = bit9_models.Bit9Binary.get_by_id(sha256)
    self.assertEqual('12345', bit9_binary.file_catalog_id)

    # Should be Empty: No new Binary or BANNED State.
    self.assertNoBigQueryInsertions()

  def testStateChangedToBanned(self):
    bit9_binary = test_utils.CreateBit9Binary(state=constants.STATE.UNTRUSTED)
    sha256 = bit9_binary.key.id()

    event_kwargs = {'subtype': bit9_constants.SUBTYPE.BANNED}
    file_catalog_kwargs = {'id': '12345', 'sha256': sha256}
    event, cert = _CreateEventAndCert(
        event_kwargs=event_kwargs, file_catalog_kwargs=file_catalog_kwargs)
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    changed = cron._PersistBit9Binary(
        event, file_catalog, [cert], datetime.datetime.utcnow()).get_result()

    self.assertTrue(changed)
    bit9_binary = bit9_models.Bit9Binary.get_by_id(sha256)
    self.assertEqual(constants.STATE.BANNED, bit9_binary.state)

    # Should be 1 for the BANNED State.
    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.BINARY])

  def testForcedInstaller_PreexistingRule_SamePolicy(self):
    bit9_binary = test_utils.CreateBit9Binary(detected_installer=False)
    test_utils.CreateBit9Rule(
        bit9_binary.key,
        is_committed=True,
        policy=constants.RULE_POLICY.FORCE_NOT_INSTALLER)
    bit9_binary.put()
    self.assertFalse(bit9_binary.is_installer)

    file_catalog_kwargs = {
        'id': bit9_binary.file_catalog_id,
        'sha256': bit9_binary.key.id(),
        'file_flags': bit9_constants.FileFlags.MARKED_NOT_INSTALLER}
    event, cert = _CreateEventAndCert(file_catalog_kwargs=file_catalog_kwargs)
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    changed = cron._PersistBit9Binary(
        event, file_catalog, [cert], datetime.datetime.utcnow()).get_result()

    self.assertFalse(changed)
    self.assertFalse(bit9_binary.key.get().is_installer)

    # Empty because Binary is not new and State is not BANNED.
    self.assertNoBigQueryInsertions()

  def testForcedInstaller_PreexistingRule_ConflictingPolicy(self):
    bit9_binary = test_utils.CreateBit9Binary(
        detected_installer=False, is_installer=False)
    test_utils.CreateBit9Rule(
        bit9_binary.key,
        is_committed=True,
        policy=constants.RULE_POLICY.FORCE_NOT_INSTALLER)

    file_catalog_kwargs = {
        'id': bit9_binary.file_catalog_id,
        'sha256': bit9_binary.key.id(),
        'file_flags': bit9_constants.FileFlags.MARKED_INSTALLER}
    event, cert = _CreateEventAndCert(file_catalog_kwargs=file_catalog_kwargs)
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    changed = cron._PersistBit9Binary(
        event, file_catalog, [cert], datetime.datetime.utcnow()).get_result()

    self.assertTrue(changed)
    self.assertTrue(bit9_binary.key.get().is_installer)

    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.RULE)

  def testNoChanges(self):
    bit9_binary = test_utils.CreateBit9Binary(detected_installer=False)

    file_catalog_kwargs = {
        'id': bit9_binary.file_catalog_id,
        'sha256': bit9_binary.key.id(),
        'file_flags': 0x0}
    event, cert = _CreateEventAndCert(file_catalog_kwargs=file_catalog_kwargs)
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    changed = cron._PersistBit9Binary(
        event, file_catalog, [cert], datetime.datetime.utcnow()).get_result()

    self.assertFalse(changed)
    # Empty because Binary is not new and State is not BANNED.
    self.assertNoBigQueryInsertions()


class PersistBanNoteTest(basetest.UpvoteTestCase):

  def testNoBans(self):
    bit9_binary = test_utils.CreateBit9Binary()

    file_catalog = bit9_test_utils.CreateFileCatalog(
        id=bit9_binary.file_catalog_id,
        sha256=bit9_binary.key.id(),
        certificate_state=bit9_constants.APPROVAL_STATE.APPROVED,
        file_state=bit9_constants.APPROVAL_STATE.APPROVED,
        publisher_state=bit9_constants.APPROVAL_STATE.APPROVED)

    self.assertEntityCount(base_models.Note, 0)
    cron._PersistBanNote(file_catalog).wait()
    self.assertEntityCount(base_models.Note, 0)

  def testNewBan(self):
    bit9_binary = test_utils.CreateBit9Binary()

    # Create FileCatalog with at least one that's BANNED.
    file_catalog = bit9_test_utils.CreateFileCatalog(
        id=bit9_binary.file_catalog_id,
        sha256=bit9_binary.key.id(),
        certificate_state=bit9_constants.APPROVAL_STATE.BANNED,
        file_state=bit9_constants.APPROVAL_STATE.APPROVED,
        publisher_state=bit9_constants.APPROVAL_STATE.APPROVED)

    self.assertEntityCount(base_models.Note, 0)
    cron._PersistBanNote(file_catalog).wait()
    self.assertEntityCount(base_models.Note, 1)

  def testDupeBan(self):
    bit9_binary = test_utils.CreateBit9Binary()

    file_catalog = bit9_test_utils.CreateFileCatalog(
        id=bit9_binary.file_catalog_id,
        sha256=bit9_binary.key.id(),
        certificate_state=bit9_constants.APPROVAL_STATE.BANNED,
        file_state=bit9_constants.APPROVAL_STATE.APPROVED,
        publisher_state=bit9_constants.APPROVAL_STATE.APPROVED)

    self.assertEntityCount(base_models.Note, 0)
    cron._PersistBanNote(file_catalog).wait()
    self.assertEntityCount(base_models.Note, 1)
    cron._PersistBanNote(file_catalog).wait()
    self.assertEntityCount(base_models.Note, 1)


class CopyLocalRulesTest(basetest.UpvoteTestCase):

  def testSuccess(self):

    binary_count = 10

    # Create a user and some corresponding Bit9Hosts.
    user = test_utils.CreateUser()
    host_1 = test_utils.CreateBit9Host(id='1111', users=[user.nickname])
    host_2 = test_utils.CreateBit9Host(id='2222', users=[user.nickname])
    host_3 = test_utils.CreateBit9Host(id='3333', users=[user.nickname])

    # Create some Bit9Binaries, each with a Bit9Rule for host_1 and host_2.
    binaries = test_utils.CreateBit9Binaries(binary_count)
    for binary in binaries:
      test_utils.CreateBit9Rule(
          binary.key, host_id=host_1.key.id(), user_key=user.key,
          in_effect=True)
      test_utils.CreateBit9Rule(
          binary.key, host_id=host_2.key.id(), user_key=user.key,
          in_effect=True)

    # Verify all the rule counts.
    self.assertEntityCount(bit9_models.Bit9Rule, binary_count * 2)
    host_1_rules = bit9_models.Bit9Rule.query(
        bit9_models.Bit9Rule.host_id == host_1.key.id()).fetch()
    self.assertEqual(binary_count, len(host_1_rules))
    host_2_rules = bit9_models.Bit9Rule.query(
        bit9_models.Bit9Rule.host_id == host_2.key.id()).fetch()
    self.assertEqual(binary_count, len(host_2_rules))
    host_3_rules = bit9_models.Bit9Rule.query(
        bit9_models.Bit9Rule.host_id == host_3.key.id()).fetch()
    self.assertEqual(0, len(host_3_rules))

    self.assertNoBigQueryInsertions()

    cron._CopyLocalRules(user.key, host_3.key.id()).get_result()

    # Verify all the rule counts again.
    self.assertEntityCount(bit9_models.Bit9Rule, binary_count * 3)
    host_1_rules = bit9_models.Bit9Rule.query(
        bit9_models.Bit9Rule.host_id == host_1.key.id()).fetch()
    self.assertEqual(binary_count, len(host_1_rules))
    host_2_rules = bit9_models.Bit9Rule.query(
        bit9_models.Bit9Rule.host_id == host_2.key.id()).fetch()
    self.assertEqual(binary_count, len(host_2_rules))
    host_3_rules = bit9_models.Bit9Rule.query(
        bit9_models.Bit9Rule.host_id == host_3.key.id()).fetch()
    self.assertEqual(binary_count, len(host_3_rules))

    self.assertBigQueryInsertions(
        [constants.BIGQUERY_TABLE.RULE] * binary_count)


class PersistBit9HostTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(PersistBit9HostTest, self).setUp()

    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  def testNewHost(self):
    users = test_utils.RandomStrings(2)
    host = bit9_test_utils.CreateComputer(
        users='{0}\\{1},{0}\\{2}'.format(settings.AD_DOMAIN, *users))
    occurred_dt = datetime.datetime.utcnow()

    self.assertEntityCount(bit9_models.Bit9Host, 0)

    cron._PersistBit9Host(host, occurred_dt).wait()

    self.assertEntityCount(bit9_models.Bit9Host, 1)
    self.assertBigQueryInsertions(
        [constants.BIGQUERY_TABLE.HOST] + [constants.BIGQUERY_TABLE.USER] * 2)

  def testUpdateLastEventDt(self):
    now_dt = datetime.datetime.utcnow()
    earlier_dt = now_dt - datetime.timedelta(days=7)
    users = test_utils.RandomStrings(2)
    policy_key = ndb.Key(bit9_models.Bit9Policy, '100')

    test_utils.CreateBit9Host(
        id='12345', last_event_dt=earlier_dt, users=users,
        policy_key=policy_key)

    host = bit9_test_utils.CreateComputer(
        id=12345,
        policy_id=100,
        users='{0}\\{1},{0}\\{2}'.format(settings.AD_DOMAIN, *users))

    cron._PersistBit9Host(host, now_dt).wait()

    bit9_host = bit9_models.Bit9Host.get_by_id('12345')
    self.assertEqual(now_dt, bit9_host.last_event_dt)
    self.assertNoBigQueryInsertions()

  def testUpdateHostname(self):
    users = test_utils.RandomStrings(2)
    policy_key = ndb.Key(bit9_models.Bit9Policy, '100')

    test_utils.CreateBit9Host(
        id='12345', hostname=bit9_utils.ExpandHostname('hostname1'),
        users=users, policy_key=policy_key)

    host = bit9_test_utils.CreateComputer(
        id=12345,
        name='hostname2',
        policy_id=100,
        users='{0}\\{1},{0}\\{2}'.format(settings.AD_DOMAIN, *users))
    occurred_dt = datetime.datetime.utcnow()

    cron._PersistBit9Host(host, occurred_dt).wait()

    bit9_host = bit9_models.Bit9Host.get_by_id('12345')
    self.assertEqual(bit9_utils.ExpandHostname('hostname2'), bit9_host.hostname)
    self.assertNoBigQueryInsertions()

  def testUpdatePolicyKey(self):
    users = test_utils.RandomStrings(2)
    old_policy_key = ndb.Key(bit9_models.Bit9Policy, '22222')

    test_utils.CreateBit9Host(
        id='11111', policy_key=old_policy_key, users=users)

    host = bit9_test_utils.CreateComputer(
        id=11111,
        policy_id=33333,
        users='{0}\\{1},{0}\\{2}'.format(settings.AD_DOMAIN, *users))
    occurred_dt = datetime.datetime.utcnow()

    cron._PersistBit9Host(host, occurred_dt).wait()

    bit9_host = bit9_models.Bit9Host.get_by_id('11111')
    new_policy_key = ndb.Key(bit9_models.Bit9Policy, '33333')
    self.assertEqual(new_policy_key, bit9_host.policy_key)
    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.HOST])

  def testUpdateHostUsers_People(self):
    old_users = test_utils.RandomStrings(2)
    new_users = test_utils.RandomStrings(2)
    policy_key = ndb.Key(bit9_models.Bit9Policy, '22222')

    test_utils.CreateBit9Host(
        id='12345', users=old_users, policy_key=policy_key)

    host = bit9_test_utils.CreateComputer(
        id=12345,
        policy_id=22222,
        users='{0}\\{1},{0}\\{2}'.format(settings.AD_DOMAIN, *new_users))
    occurred_dt = datetime.datetime.utcnow()

    cron._PersistBit9Host(host, occurred_dt).wait()

    # Verify that the users were updated in Datastore.
    host = bit9_models.Bit9Host.get_by_id('12345')
    self.assertSameElements(new_users, host.users)

    # Verify all BigQuery row persistence.
    self.assertBigQueryInsertions(
        [constants.BIGQUERY_TABLE.HOST] + [constants.BIGQUERY_TABLE.USER] * 2)

  def testUpdateHostUsers_WindowManager(self):

    test_utils.CreateBit9Host(
        id='12345',
        users=['a_real_person'],
        policy_key=ndb.Key(bit9_models.Bit9Policy, '22222'))

    host = bit9_test_utils.CreateComputer(
        id=12345,
        policy_id=22222,
        users=r'Window Manager\DWM-999')
    occurred_dt = datetime.datetime.utcnow()

    cron._PersistBit9Host(host, occurred_dt).wait()

    # Verify that the user didn't get updated.
    host = bit9_models.Bit9Host.get_by_id('12345')
    self.assertSameElements(['a_real_person'], host.users)

    # Verify no BigQuery row persistence.
    self.assertNoBigQueryInsertions()

  def testUpdateHostUsers_NoIncomingUsers(self):

    old_users = test_utils.RandomStrings(2)
    policy_key = ndb.Key(bit9_models.Bit9Policy, '22222')

    test_utils.CreateBit9Host(
        id='12345', users=old_users, policy_key=policy_key)

    host = bit9_test_utils.CreateComputer(
        id=12345, policy_id=22222, users='')
    occurred_dt = datetime.datetime.utcnow()

    cron._PersistBit9Host(host, occurred_dt).wait()

    # Verify that the users weren't updated in Datastore.
    host = bit9_models.Bit9Host.get_by_id('12345')
    self.assertSameElements(old_users, host.users)


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

    result = cron._CheckAndResolveAnomalousBlock(bit9_binary.key, '12345')
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
    self.assertEntityCount(bit9_models.RuleChangeSet, 0)

    result = cron._CheckAndResolveAnomalousBlock(bit9_binary.key, '12345')
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
    self.assertEntityCount(bit9_models.RuleChangeSet, 1)

    # Verify the deferred commit to Bit9.
    self.assertTrue(change_set.DeferCommitBlockableChangeSet.called)


class PersistBit9EventsTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(PersistBit9EventsTest, self).setUp()
    self.Patch(cron, '_CheckAndResolveAnomalousBlock', return_value=False)

  def testSuccess_ExecutingUser(self):
    event, cert = _CreateEventAndCert()
    file_catalog = event.get_expand(api.Event.file_catalog_id)
    computer = event.get_expand(api.Event.computer_id)

    self.assertEntityCount(bit9_models.Bit9Event, 0)
    cron._PersistBit9Events(
        event, file_catalog, computer, [cert]).wait()
    self.assertEntityCount(bit9_models.Bit9Event, 1)

    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.EXECUTION])

  def testSuccess_LocalAdmin(self):
    users = '{0}\\foobar,{0}\\bazqux'.format(settings.AD_DOMAIN)
    computer = bit9_test_utils.CreateComputer(users=users)
    event_kwargs = {'user_name': constants.LOCAL_ADMIN.WINDOWS}
    computer_kwargs = {'users': users}
    event, cert = _CreateEventAndCert(
        event_kwargs=event_kwargs, computer_kwargs=computer_kwargs)
    file_catalog = event.get_expand(api.Event.file_catalog_id)

    self.assertEntityCount(bit9_models.Bit9Event, 0)
    cron._PersistBit9Events(
        event, file_catalog, computer, [cert]).wait()
    self.assertEntityCount(bit9_models.Bit9Event, 2)

    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.EXECUTION])


class CronTest(basetest.UpvoteTestCase):

  def setUp(self, **kwargs):
    super(CronTest, self).setUp(**kwargs)
    self.Patch(bit9_utils, 'CONTEXT')

  def _PatchApiRequests(self, *results):
    requests = []
    for batch in results:
      if isinstance(batch, list):
        requests.append([obj.to_raw_dict() for obj in batch])
      else:
        requests.append(batch.to_raw_dict())
    bit9_utils.CONTEXT.ExecuteRequest.side_effect = requests


class CommitAllChangeSetsTest(CronTest):

  def setUp(self):
    app = webapp2.WSGIApplication([
        webapp2.Route(
            '/', handler=cron.CommitAllChangeSets)])
    super(CommitAllChangeSetsTest, self).setUp(wsgi_app=app)

  @mock.patch.object(cron.monitoring, 'pending_changes')
  def testAll(self, mock_metric):
    binary = test_utils.CreateBit9Binary()
    change = test_utils.CreateRuleChangeSet(binary.key)
    other_binary = test_utils.CreateBit9Binary()
    # Create two changesets so we're sure we're doing only 1 task per blockable.
    real_change = test_utils.CreateRuleChangeSet(other_binary.key)
    unused_change = test_utils.CreateRuleChangeSet(other_binary.key)
    self.assertTrue(real_change.recorded_dt < unused_change.recorded_dt)

    self.testapp.get('/')

    self.assertEqual(2, mock_metric.Set.call_args_list[0][0][0])
    self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 2)
    with mock.patch.object(change_set, '_CommitChangeSet') as mock_commit:
      self.RunDeferredTasks(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE)

      expected_calls = [mock.call(change.key), mock.call(real_change.key)]
      self.assertSameElements(expected_calls, mock_commit.mock_calls)



class UpdateBit9PoliciesTest(CronTest):

  def setUp(self):
    app = webapp2.WSGIApplication([('/', cron.UpdateBit9Policies)])
    super(UpdateBit9PoliciesTest, self).setUp(wsgi_app=app)

  def _PatchApiRequests(self, *results):
    requests = []
    for batch in results:
      if isinstance(batch, list):
        requests.append([obj.to_raw_dict() for obj in batch])
      else:
        requests.append(obj.to_raw_dict())
    bit9_utils.CONTEXT.ExecuteRequest.side_effect = requests

  def testGet_CreateNewPolicy(self):
    policy = api.Policy(id=1, name='foo', enforcement_level=20)
    self._PatchApiRequests([policy])

    self.testapp.get('/')

    policies = bit9_models.Bit9Policy.query().fetch()
    self.assertEqual(1, len(policies))

    policy = policies[0]
    self.assertEqual('1', policy.key.id())
    self.assertEqual('foo', policy.name)
    self.assertEqual(
        constants.BIT9_ENFORCEMENT_LEVEL.LOCKDOWN, policy.enforcement_level)

  def testGet_UpdateChangedPolicy(self):
    policy_obj_1 = bit9_models.Bit9Policy(
        id='1', name='bar',
        enforcement_level=constants.BIT9_ENFORCEMENT_LEVEL.LOCKDOWN)
    policy_obj_1.put()
    old_policy_dt = policy_obj_1.updated_dt

    policy_obj_2 = bit9_models.Bit9Policy(
        id='2', name='baz',
        enforcement_level=constants.BIT9_ENFORCEMENT_LEVEL.LOCKDOWN)
    policy_obj_2.put()
    old_other_policy_dt = policy_obj_2.updated_dt

    policy1 = api.Policy(id=1, name='foo', enforcement_level=30)
    policy2 = api.Policy(id=2, name='baz', enforcement_level=20)
    self._PatchApiRequests([policy1, policy2])

    self.testapp.get('/')

    self.assertEqual(2, bit9_models.Bit9Policy.query().count())

    # First policy should have has its name updated from 'bar' to 'foo'.
    updated_policy = bit9_models.Bit9Policy.get_by_id('1')
    self.assertEqual('foo', updated_policy.name)
    self.assertEqual(
        constants.BIT9_ENFORCEMENT_LEVEL.BLOCK_AND_ASK,
        updated_policy.enforcement_level)
    self.assertNotEqual(old_policy_dt, updated_policy.updated_dt)

    # Second policy should be unchanged.
    other_updated_policy = bit9_models.Bit9Policy.get_by_id('2')
    self.assertEqual(old_other_policy_dt, other_updated_policy.updated_dt)

  def testGet_IgnoreBadEnforcementLevel(self):
    policy_obj = bit9_models.Bit9Policy(
        id='1', name='foo',
        enforcement_level=constants.BIT9_ENFORCEMENT_LEVEL.LOCKDOWN)
    policy_obj.put()

    # Updated to an unknown enforcement level.
    policy = api.Policy(id=1, name='bar', enforcement_level=25)
    self._PatchApiRequests([policy])

    self.testapp.get('/')

    # Policy name should _not_ be updated.
    updated_policy = bit9_models.Bit9Policy.get_by_id('1')
    self.assertEqual('foo', updated_policy.name)


class CountEventsToPullTest(CronTest):

  def setUp(self):
    app = webapp2.WSGIApplication([('/', cron.CountEventsToPull)])
    super(CountEventsToPullTest, self).setUp(wsgi_app=app)

  @mock.patch.object(cron.monitoring, 'events_to_pull')
  def testSuccess(self, mock_metric):
    bit9_utils.CONTEXT.ExecuteRequest.return_value = {'count': 20}

    self.testapp.get('/')

    actual_length = mock_metric.Set.call_args_list[0][0][0]
    self.assertEqual(20, actual_length)


class PullEventsTest(CronTest):

  def setUp(self):
    app = webapp2.WSGIApplication([('/', cron.PullEvents)])
    super(PullEventsTest, self).setUp(wsgi_app=app)

  def testQueueFills(self):
    for i in xrange(1, cron._PULL_MAX_QUEUE_SIZE + 20):
      response = self.testapp.get('/')
      self.assertEqual(httplib.OK, response.status_int)
      expected_queue_size = min(i, cron._PULL_MAX_QUEUE_SIZE)
      self.assertTaskCount(constants.TASK_QUEUE.BIT9_PULL, expected_queue_size)


class CountEventsToProcessTest(CronTest):

  def setUp(self):
    app = webapp2.WSGIApplication([('/', cron.CountEventsToProcess)])
    super(CountEventsToProcessTest, self).setUp(wsgi_app=app)

  @mock.patch.object(cron.monitoring, 'events_to_process')
  def testSuccess(self, mock_metric):
    expected_length = 5
    for _ in xrange(expected_length):
      cron._UnsyncedEvent().put()

    response = self.testapp.get('/')

    self.assertEqual(httplib.OK, response.status_int)
    actual_length = mock_metric.Set.call_args_list[0][0][0]
    self.assertEqual(expected_length, actual_length)


class ProcessEventsTest(CronTest):

  def setUp(self):
    app = webapp2.WSGIApplication([('/', cron.ProcessEvents)])
    super(ProcessEventsTest, self).setUp(wsgi_app=app)

  def testQueueFills(self):
    for i in xrange(1, cron._DISPATCH_MAX_QUEUE_SIZE + 20):
      response = self.testapp.get('/')
      self.assertEqual(httplib.OK, response.status_int)
      expected_queue_size = min(i, cron._DISPATCH_MAX_QUEUE_SIZE)
      self.assertTaskCount(
          constants.TASK_QUEUE.BIT9_DISPATCH, expected_queue_size)


if __name__ == '__main__':
  absltest.main()
