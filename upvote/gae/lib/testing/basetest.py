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

"""Base TestCase for Upvote AppEngine unit tests."""

import base64
import collections
import contextlib
import logging
import os
import pickle

import mock
from oauth2client.contrib import xsrfutil
import webapp2
from webapp2_extras import routes
import webtest

from google.appengine.api import memcache
from google.appengine.api import users
from google.appengine.datastore import datastore_stub_util

from common.testing import basetest

from upvote.gae import settings
from upvote.gae.bigquery import tables
from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import singleton
from upvote.gae.utils import env_utils
from upvote.gae.utils import handler_utils
from upvote.shared import constants


def _ExtractRoutes(wsgi_app):
  queue = collections.deque(wsgi_app.router.match_routes)
  while queue:
    route = queue.popleft()
    if isinstance(route, webapp2.Route):
      yield route
    elif isinstance(route, routes.PathPrefixRoute):
      queue.extendleft(route.routes)


class UpvoteTestCase(basetest.AppEngineTestCase):
  """Base TestCase for Upvote AppEngine unit tests."""

  def setUp(
      self, wsgi_app=None, patch_generate_token=True,
      patch_send_to_bigquery=True):

    super(UpvoteTestCase, self).setUp()

    # Require index.yaml be observed so tests will fail if indices are absent.
    index_yaml_dir = os.path.join(
        os.path.dirname('.'), 'upvote/gae')
    policy = datastore_stub_util.PseudoRandomHRConsistencyPolicy(probability=1)
    self.testbed.init_datastore_v3_stub(
        consistency_policy=policy, require_indexes=True,
        root_path=index_yaml_dir)
    self.testbed.init_memcache_stub()

    if wsgi_app is not None:
      # Workaround for lack of "runtime" variable in test env.
      adapter = lambda r, h: webapp2.Webapp2HandlerAdapter(h)
      wsgi_app.router.set_adapter(adapter)

      # Make note of the routes being registered for easier debugging.
      for route in _ExtractRoutes(wsgi_app):
        logging.info('Registering route %s', route.template)

      handler_utils.ConfigureErrorHandlers(wsgi_app)
      self.testapp = webtest.TestApp(wsgi_app)
    else:
      self.testapp = None

    # NOTE: PatchEnv() needs to be called before the xsrf_utils bit below. The
    # call to Singleton.SetInstance() eventually imports appengine_config.py,
    # which will attempt to make some BigQuery insertions, which then fail with
    # UnknownEnvironmentError unless we've already patched the environment
    # detection.
    self._env_patcher = None
    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

    # Patch out the call that streams to BigQuery so it can be verified in
    # assertBigQueryInsertions() below.
    if patch_send_to_bigquery:
      self.mock_send_to_bigquery = self.Patch(tables, '_SendToBigQuery')

    self.secret_key = 'test-secret'
    singleton.SiteXsrfSecret.SetInstance(secret=self.secret_key.encode('hex'))

    if patch_generate_token:
      self.Patch(xsrfutil, 'generate_token', return_value='token')

  def tearDown(self):
    super(UpvoteTestCase, self).tearDown()

    # Ensure that there are no lingering, unverified BigQuery rows in the queue.
    # Any test that results in a BigQuery row being generated should also be
    # calling UpvoteTestCase.DrainTaskQueue() and verifying that the drained
    # rows pass validation.
    if hasattr(self, 'mock_send_to_bigquery'):
      self.assertNoBigQueryInsertions()

    self.UnpatchEnv()

  @contextlib.contextmanager
  def LoggedInUser(self, user=None, email_addr=None, admin=False):

    # Start with a logout just in case there is already an active login.
    previous_user = users.get_current_user()
    self.Logout()

    # Create a new user if needed.
    if not user:
      user = test_utils.CreateUser(admin=admin, email=email_addr)

    # Log in as the newly-created user.
    self.Login(user.email)

    # Yield the entity out into the surrounded context.
    yield user

    # Once we're finished, log out.
    self.Logout()

    # If there was an existing login, restore it.
    if previous_user:
      self.Login(previous_user.email())

  def PatchSetting(self, setting, value):
    patcher = mock.patch.dict(settings.__dict__, values={setting: value})
    self.addCleanup(patcher.stop)
    return patcher.start()

  def VerifyIncrementCalls(self, mock_metric, *args):
    """Verifies the Increment() calls of a given mock metric.

    Args:
      mock_metric: The mock metric to verify.
      *args: The expected arguments of the Increment() calls.
    """
    expected_args = list(args)
    expected_call_count = len(expected_args)

    increment_calls = mock_metric.Increment.call_args_list
    actual_args = [c[0][0] for c in increment_calls]

    self.assertEqual(expected_call_count, mock_metric.Increment.call_count)
    self.assertEqual(expected_args, actual_args)

  def assertEntityCount(self, model_class, expected_count, ancestor=None):  # pylint: disable=g-bad-name
    actual_count = model_class.query(ancestor=ancestor).count(keys_only=True)
    self.assertEqual(expected_count, actual_count)

  def assertEntitiesExist(self, model_class, ancestor=None):
    count = model_class.query(ancestor=ancestor).count(keys_only=True)
    self.assertGreater(count, 0)

  def assertNoEntitiesExist(self, model_class, ancestor=None):
    self.assertEntityCount(model_class, 0, ancestor=ancestor)

  def assertTaskCount(self, queue_name, expected_count):  # pylint: disable=g-bad-name
    self.assertLen(self.GetTasks(queue_name), expected_count)

  def assertMemcacheContains(self, key, expected_value, namespace=None):
    actual_value = memcache.get(key, namespace=namespace)
    self.assertEqual(expected_value, actual_value)

  def assertMemcacheLacks(self, key, namespace=None):
    self.assertIsNone(memcache.get(key, namespace=namespace))

  def assertBigQueryInsertions(self, table_names, reset_mock=True):
    """Verifies that all outstanding BigQuery insertions match expectations.

    Args:
      table_names: A list of strings, each of which must be a valid BigQuery
          table name. The list should represent the exact tables that are
          expected to have row insertions, and how many insertions there should
          be. For example, two insertions to table X and one insertion to table
          Y could be represented as ['X', 'Y', 'X']. Order is not important.
      reset_mock: Whether to reset the _SendToBigQuery() mock or not. If the
          actual arguments passed to the mock need to be tested, this should be
          False.
    """
    # Verify that all provided table names are valid.
    for table_name in table_names:
      self.assertIn(
          table_name, constants.BIGQUERY_TABLE.SET_ALL,
          msg='Invalid table name provided (%s)' % table_name)

    expected_insertions = sorted(table_names)

    # Examine the task queue and note which insertions were actually queued.
    tasks = self.UnpackTaskQueue(
        queue_name=constants.TASK_QUEUE.BIGQUERY_STREAMING, flush=False)
    queued_insertions = sorted(task[1][0].name for task in tasks)

    # Verify that the expected insertions match the queued insertions.
    if expected_insertions != queued_insertions:
      msg_lines = [
          'Expected insertions do not match queued insertions: %s != %s' % (
              expected_insertions, queued_insertions)]
      if tasks:
        msg_lines.append('Queued insertions:')
        msg_lines.extend('%s: %s' % (t[1][0].name, t[2]) for t in tasks)
      msg = '\n\n'.join(msg_lines)
      self.assertListEqual(expected_insertions, queued_insertions, msg=msg)

    # Run the deferred insertion tasks. This ensures that they all go through
    # validation and attempt to call BigQuery.
    self.DrainTaskQueue(constants.TASK_QUEUE.BIGQUERY_STREAMING)

    # Examine the mock and note which insertions were actually performed.
    # calls = self.mock_send_to_bigquery.call_args_list
    calls = self.GetBigQueryCalls(reset_mock=False)
    actual_insertions = sorted(c[0].name for c in calls)

    # Verify that the table insertions match the expectations. If they don't,
    # display the detailed info about the actual insertions that were performed,
    # for easier debugging. Failures here should be due to validation errors.
    if expected_insertions != actual_insertions:
      msg_lines = [
          'Expected insertions do not match actual insertions: %s != %s' % (
              expected_insertions, actual_insertions)]
      if calls:
        msg_lines.append('Actual insertions:')
        msg_lines.extend('%s: %s' % (c[0], c[1]) for c in calls)
      msg = '\n\n'.join(msg_lines)
      self.assertListEqual(expected_insertions, actual_insertions, msg=msg)

    if reset_mock:
      self.mock_send_to_bigquery.reset_mock()

  def assertBigQueryInsertion(self, table_name, reset_mock=True):
    """Verifies that all outstanding BigQuery insertions match expectations.

    Args:
      table_name: A string which must be a valid BigQuery table name. The string
          represents the table that is expected to have a row insertion.
      reset_mock: Whether to reset the _SendToBigQuery() mock or not. If the
          actual arguments passed to the mock need to be tested, this should be
          False.
    """
    self.assertBigQueryInsertions([table_name], reset_mock=reset_mock)

  def GetBigQueryCalls(self, predicate=None, reset_mock=True):
    """Returns a list of tuples, representing the args of _SendToBigQuery().

    Args:
      predicate: A function to optionally filter the list of tuples with.
      reset_mock: Whether to reset the _SendToBigQuery() mock or not. If the
          actual arguments passed to the mock need to be tested, this should be
          False.

    Returns:
      A list of (str, str, dict) tuples, corresponding to the args send to the
          tables._SendToBigQuery() mock.
    """
    calls = self.mock_send_to_bigquery.call_args_list
    call_args = [(c[0][0], c[0][1]) for c in calls]
    if reset_mock:
      self.mock_send_to_bigquery.reset_mock()
    return filter(predicate, call_args)

  def assertNoBigQueryInsertions(self):
    self.assertBigQueryInsertions([])

  def Patch(self, target, attribute, **kwargs):
    patcher = mock.patch.object(target, attribute, **kwargs)
    self.addCleanup(patcher.stop)
    return patcher.start()

  def PatchEnv(self, new_env=None, **new_settings):
    self.UnpatchEnv()

    # Create a dummy environment if one wasn't provided.
    if new_env is None:
      class DummyEnv(env_utils.DefaultEnv):
        pass

      new_env = DummyEnv()

    # Override/set any settings provided as kwargs.
    if new_settings:
      for name, value in new_settings.iteritems():
        setattr(new_env, name, value)

    self._env_patcher = mock.patch.object(
        env_utils, 'ENV', new_callable=mock.PropertyMock(return_value=new_env))
    self._env_patcher.start()

  def UnpatchEnv(self):
    if self._env_patcher:
      self._env_patcher.stop()
      self._env_patcher = None

  def PatchValidateXSRFToken(self):
    self.Patch(xsrfutil, 'validate_token')

  def GetTasks(self, queue_name=constants.TASK_QUEUE.DEFAULT):
    """Returns the contents of a task queue (fixing the empty-queue case)."""
    # taskqueue_stub.GetTasks raises a KeyError if no task has been added so we
    # check for this case manually.
    try:
      return self.taskqueue_stub.GetTasks(queue_name)
    except KeyError:
      return []

  def DrainTaskQueue(self, queue_name, limit=None):
    """Runs all tasks in the given queue, even those created by prior tasks.

    This method is loosely based on AppEngineTestCase.RunDeferredTasks. It has
    two advantages over that method though:
      1) It will run all tasks, even those spawned from previous tasks.
      2) It won't fail with a KeyError if the given queue is empty.

    Args:
      queue_name: The name of the task queue.
      limit: The maximum number of tasks to run. If None, no limit is imposed.
    """
    keep_running = True
    tasks_run = 0

    while keep_running:

      tasks = self.GetTasks(queue_name)
      keep_running = bool(tasks)

      for task in tasks:

        self._RunDeferredTask(queue_name, task, True)
        tasks_run += 1

        # If there's a limit and it was just hit, bail.
        if limit and tasks_run >= limit:
          keep_running = False
          break

  def FlushTaskQueue(self, queue_name=constants.TASK_QUEUE.DEFAULT):
    self.taskqueue_stub.FlushQueue(queue_name)

  def UnpackTaskQueue(
      self, queue_name=constants.TASK_QUEUE.DEFAULT, flush=True):
    """Unpacks the contents of a specified task queue.

    Args:
      queue_name: The name of the task queue to unpack.
      flush: Whether or not to flush the contents of the task queue.

    Returns:
      A list of unpickled task queue payloads. Each item in the list is a
      triple of the form (function, list, dict). The function is the actual
      function object that was deferred to the task queue. The list contains all
      args passed to that function, and the dict contains all kwargs.
    """
    tasks = self.GetTasks(queue_name)
    if flush:
      self.FlushTaskQueue(queue_name=queue_name)
    # Unpack the task payloads.
    return [pickle.loads(base64.b64decode(task['body'])) for task in tasks]


def main():
  basetest.main()
