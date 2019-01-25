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

"""A base test for App Engine tests.

This testing utility library stubs out relevant App Engine services and sets up
an environment similar to how an app might run in the Python 2.7 runtime.

Usage:
  class MyTest(basetest.AppEngineTestCase):
    def testMyTest(self):
      # Do everything here, the environment should be correct.

      # Some helpful methods:
      self.RunDeferredTasks()
      self.Login('example@example.com', is_admin=False)
      self.Logout()
      self.SetHostname('testbed.example.com')

  if __name__ == '__main__':
    basetest.main()
"""

import base64
import os
import random
import string

from google.appengine.api import apiproxy_stub_map
from google.appengine.datastore import datastore_stub_util
from google.appengine.ext import deferred
from google.appengine.ext import testbed
from google.appengine.runtime import request_environment
from google.appengine.runtime import runtime
from absl.testing import absltest


from google.appengine.api.search import simple_search_stub


# Replace start_new_thread with a version where new threads inherit os.environ
# from their creator thread.
runtime.PatchStartNewThread()


def main():
  """Simple wrapper to call absltest.main()."""
  return absltest.main()


class AppEngineTestCase(absltest.TestCase):

  def setUp(self):
    """Initializes the App Engine stubs."""
    # Evil os-environ patching which mirrors dev_appserver and production.
    # This patch turns os.environ into a thread-local object, which also happens
    # to support storing more than just strings. This patch must come first.
    self._old_os_environ = os.environ.copy()
    request_environment.current_request.Clear()
    request_environment.PatchOsEnviron()
    os.environ.update(self._old_os_environ)

    # Setup and activate the testbed.
    self.InitTestbed()

    # Register the search stub (until included in init_all_stubs).
    if (simple_search_stub and
        apiproxy_stub_map.apiproxy.GetStub('search') is None):
      self.search_stub = simple_search_stub.SearchServiceStub()
      apiproxy_stub_map.apiproxy.RegisterStub('search', self.search_stub)

    # Fake an always strongly-consistent HR datastore.
    policy = datastore_stub_util.PseudoRandomHRConsistencyPolicy(probability=1)
    self.testbed.init_datastore_v3_stub(consistency_policy=policy)
    self.datastore_stub = self.testbed.get_stub(testbed.DATASTORE_SERVICE_NAME)

    # Save the taskqueue_stub for use in RunDeferredTasks.
    self.testbed.init_taskqueue_stub(_all_queues_valid=True)
    self.taskqueue_stub = self.testbed.get_stub(testbed.TASKQUEUE_SERVICE_NAME)

    # Save other stubs for use in helper methods and tests.
    self.users_stub = self.testbed.get_stub(testbed.USER_SERVICE_NAME)
    self.channel_stub = self.testbed.get_stub(testbed.CHANNEL_SERVICE_NAME)

    # Each time setUp is called, treat it like a different request to a
    # different app instance.
    request_id_hash = ''.join(random.sample(string.letters + string.digits, 26))
    instance_id = ''.join(random.sample(string.letters + string.digits, 26))
    # More like the production environment: "testbed-version.123123123", rather
    # than the default "testbed-version".
    current_version_id = 'testbed-version.%s' % random.randint(1, 1000000000000)
    self.testbed.setup_env(
        request_id_hash=request_id_hash, instance_id=instance_id,
        current_version_id=current_version_id, overwrite=True)

    self.Logout()
    super(AppEngineTestCase, self).setUp()

  def tearDown(self):
    os.environ = self._old_os_environ
    self.testbed.deactivate()
    super(AppEngineTestCase, self).tearDown()

  def InitTestbed(self):
    self.testbed = testbed.Testbed()
    self.testbed.activate()
    self.testbed.init_all_stubs()

  def Login(self, email, user_id='1', organization=None, is_admin=False,
            is_oauth_user=False, scopes=None):
    """Logs in as a user.

    Args:
      email: The email of the user.
      user_id: The user ID.
      organization: The hostname of the org the user belongs to.
      is_admin: Whether this is an admin user.
      is_oauth_user: Whether to log the user in as an OAuth user.
      scopes: List of valid scopes (used for OAuth).
    """
    self.Logout()
    if organization is None:
      organization = email.split('@')[-1] if email else ''

    if is_oauth_user:
      self.users_stub.SetOAuthUser(
          email=email, user_id=user_id, domain=organization, is_admin=is_admin,
          scopes=scopes)
      os.environ['HTTP_AUTHORIZATION'] = 'Bearer 1/accesstoken'
    else:
      self.testbed.setup_env(
          overwrite=True,
          user_email=email,
          user_id=user_id,
          user_organization=organization,
          user_is_admin=('1' if is_admin else '0'),
      )

  def Logout(self):
    """Logs the user out."""
    self.testbed.setup_env(
        overwrite=True,
        user_id='',
        user_email='',
    )
    # Log out the OAuth user.
    self.users_stub.SetOAuthUser(email=None)
    if 'OAUTH_ERROR_CODE' in os.environ:
      del os.environ['OAUTH_ERROR_CODE']
    if 'HTTP_AUTHORIZATION' in os.environ:
      del os.environ['HTTP_AUTHORIZATION']

  def RunDeferredTasks(self, queue_name='default', runs=None, delete=True):
    """Runs all of the deferred tasks in a particular queue.

    This method mimics a task environment by running as an anonymous admin user.

    Args:
      queue_name: The name of the task queue.
      runs: The number of tasks to process.
      delete: Whether or not to delete the task after running.
    """
    tasks = self.taskqueue_stub.GetTasks(queue_name)
    for i, task in enumerate(tasks):
      if runs and i == runs:
        break
      self._RunDeferredTask(queue_name, task, delete)

  def _RunDeferredTask(self, queue_name, task, delete):
    """Runs a deferred task as an anonymous admin user."""
    # Deferred tasks run as an anonymous admin user.
    environ = os.environ.copy()
    self.Logout()
    os.environ['USER_IS_ADMIN'] = '1'
    # Add the task-specific HTTP headers.
    for header, value in task['headers']:
      key = 'HTTP_' + header.upper().replace('-', '_')
      os.environ[key] = value
    try:
      deferred.run(base64.b64decode(task['body']))
    finally:
      if delete:
        self.taskqueue_stub.DeleteTask(queue_name, task['name'])
    os.environ = environ

  def SetHostname(self, hostname, port=80, default_version_hostname=None):
    """Sets the hostname environ variables."""
    self.testbed.setup_env(
        default_version_hostname=default_version_hostname or hostname,
        # Make sure code is compatible with dev_appserver by always adding port:
        http_host='%s:%s' % (hostname, port),
        overwrite=True,
        server_name=hostname,
    )
