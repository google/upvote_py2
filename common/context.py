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


from __future__ import with_statement

"""Information about the context an app is running in."""



import datetime
import os
import random
import sys
import threading
import weakref

from google.appengine.api import namespace_manager
from google.appengine.api import users

# True if the app is running inside the dev appserver, false otherwise.  This
# is not the opposite of IS_RUNNING_IN_PRODUCTION; it is possible (in tests,
# for example) for both IS_RUNNING_IN_DEV_APPSERVER and IS_RUNNING_IN_PRODUCTION
# to be false.
IS_RUNNING_IN_DEV_APPSERVER = (
    os.getenv('SERVER_SOFTWARE') and
    os.getenv('SERVER_SOFTWARE').startswith('Development/'))
# True if the app is running inside an AppEngine production environment, such
# as prom.corp or appspot.com.  False if it's running inside dev_appserver or
# unsupported (such as from unit tests).
IS_RUNNING_IN_PRODUCTION = (
    os.getenv('SERVER_SOFTWARE') and
    os.getenv('SERVER_SOFTWARE').startswith('Google App Engine/'))
# If running in production, the major.minor version of the currently running
# application.  If running in development, dev.<random number>.
APP_VERSION = (IS_RUNNING_IN_PRODUCTION and
               os.getenv('CURRENT_VERSION_ID', '0.0') or
               'dev.%s' % random.randrange(sys.maxint))

_STABLE_UTCNOW_ENV_MARKER_NAME = 'STABLE_UTCNOW_ENV_MARKER'
# We use non-compliant names for better parity with datetime.utcnow.
# pylint: disable=g-bad-name
_stable_utcnow = None
_live_utcnow = None


def live_utcnow():
  """Returns datetime.datetime.utcnow(), but can be overridden for testing."""
  return _live_utcnow or datetime.datetime.utcnow()


def SetLiveUtcNowForTesting(now):
  """Sets the value to be returned by live_utcnow for testing."""
  global _live_utcnow  # pylint: disable=global-statement
  _live_utcnow = now


def stable_utcnow():
  """Returns a current datetime.utcnow() that doesn't change during a request.

  You can use stable_utcnow to make sure that timedeltas computed against utcnow
  in various areas of your code are consistent with each other without having to
  inject an explicit datetime into each one.

  Returns:
    A datetime object that falls between the start of the current request and
    live_utcnow(), and is the same on repeated calls during the same
    request.
  """
  # Environment variables are wiped between requests and module variables aren't
  if not os.getenv(_STABLE_UTCNOW_ENV_MARKER_NAME, None):
    SetStableUtcNowForTesting(live_utcnow())
  return _stable_utcnow


def SetStableUtcNowForTesting(now):
  """Sets a value to be returned by stable_utcnow(), for testing."""
  global _stable_utcnow  # pylint: disable=global-statement
  _stable_utcnow = now
  os.environ[_STABLE_UTCNOW_ENV_MARKER_NAME] = str(_stable_utcnow)


def GetCurrentUsername():
  """Returns the username of the signed in user, if any.

  If the email address of the signed in user belongs to a domain other than the
  current request's namespace, returns the entire email address instead to avoid
  confusion.  (We don't want to raise an exception since those get swallowed
  when rendering templates, which is where this function is most likely to be
  used.)

  Returns:
    The username or email address of the currently signed in user, or an empty
    string if no one is signed in.
  """
  user = users.get_current_user()
  if not user: return ''
  username, domain = user.email().split('@', 1)
  if domain == namespace_manager.get_namespace():
    return username
  return user.email()


def IsCurrentRequestFromBlobstore():
  """Checks whether the current request came from a Blobstore callback.

  Returns:
    True if the request came from Blobstore, False otherwise.
  """
  return (
      os.getenv('REMOTE_ADDR', None) == '0.1.0.30' or
      not IS_RUNNING_IN_PRODUCTION)


def IsCurrentRequestInternal():
  """Checks whether the current request came from an internal AppEngine process.

  For example, this covers callbacks from Cron, task queues, warming requests,
  various services (including Blobstore above), etc.

  Returns:
    True if the request came from an internal AppEngine process, False
    otherwise.
  """
  return (
      os.getenv('REMOTE_ADDR', '').startswith('0.1.0.') or
      not IS_RUNNING_IN_PRODUCTION)


def IsCurrentRequestFromCron():
  """Checks whether the current request came from a cron job.

  Returns:
    True if the request came from a cron.
  """
  return (
      os.getenv('REMOTE_ADDR', '').startswith('0.1.0.1') or
      not IS_RUNNING_IN_PRODUCTION)


def IsCurrentRequestATask():
  """Checks whether the current request is a task.

  Returns:
    True if the request is a task.
  """
  return (
      os.getenv('REMOTE_ADDR', '').startswith('0.1.0.2') or
      not IS_RUNNING_IN_PRODUCTION)


def IsCurrentRequestInteractive():
  """Checks whether the current request is interactive, i.e. not task or cron.

  Returns:
    True if the request is interactive.
  """
  return not (IsCurrentRequestATask() or IsCurrentRequestFromCron())


# A list of weak references to all LazyProxy objects that have been created
_lazy_proxy_references = []


def LazyProxy(fn):
  """Function decorator for lazy proxy initializers.

  Use this decorator when you'd like to declare a module-level constant but
  can't initialize it at module load time for some reason.  (A common reason is
  that you're creating a service wrapper that opens a connection to a backend,
  but you need to register the appropriate AppEngine stubs in your tests
  beforehand.)  You can use the name of the decorated function as if it was a
  constant (don't try to call it!)  The decorated function will be used to
  construct an instance of your service the first time it's accessed.  Example:

    @LazyProxy
    def MY_SERVICE():
      return MyServiceWrapper('https://myservice.com/api/v1')

    def GetSomeThings():
      MY_SERVICE.GetThings(query='key:value')

  Note that the lazy proxy returned by the decorator will only forward attribute
  lookups to the actual service.  Attribute writes and special methods (__str__
  and  the like) will not be forwarded as the semantics become a bit surprising.
  This page shows how to do it and (implicitly) why it's not a good idea:
  http://code.activestate.com/recipes/496741-object-proxying/.

  Args:
    fn: callable.  The function that creates a new instance of the target
        object.  It will be called at most once, with no arguments.

  Returns:
    A proxy for the object created by the function.
  """
  return _LazyProxyObject(fn)


def ResetLazyProxies():
  """Resets all lazy proxies that still exist. For use in tests only."""
  for proxy_ref in _lazy_proxy_references:
    proxy = proxy_ref()
    if proxy:
      # Accessing '_LazyProxyObject__value_constructed' is necessary in order to
      # reset proxies
      proxy._LazyProxyObject__value_constructed = False
      # Attempting to delete the attribute blindly will fail if the proxy wasn't
      # resolved, and checking hasattr causes the proxy to resolve!  Instead,
      # just reset to None to assist garbage collection; the value will be
      # ignored anyway since value_constructed is False.
      proxy._LazyProxyObject__value = None


class _LazyProxyObject(object):
  __slots__ = (
      '__constructor', '__lock', '__value_constructed', '__value', '__weakref__'
      )
  # A slotted class doesn't have a __dict__.  However, some clients attempt to
  # access it anyway, which will delegate to __getattr__ and attempt to create
  # the value.  If creating the value causes the client to attempt to access
  # __dict__ again (such as with AppStats and a lazy service initializer), we
  # descend into infinite recursion.
  __dict__ = {}

  def __init__(self, constructor):
    self.__lock = threading.Lock()
    self.__constructor = constructor
    self.__value_constructed = False
    _lazy_proxy_references.append(weakref.ref(self))

  def __GetValue(self):
    if not self.__value_constructed:
      # Grab the lock inside of here to avoid locking for every
      # object access.
      with self.__lock:
        if not self.__value_constructed:
          self.__value = self.__constructor()
          self.__value_constructed = True
    return self.__value

  def __getattr__(self, name):
    return getattr(self.__GetValue(), name)

  # We'd rather not meddle with setattr, but it's required for mocking in tests.
  def __setattr__(self, name, value):
    class_name = _LazyProxyObject.__name__
    if name.startswith(class_name) and name[len(class_name):] in self.__slots__:
      object.__setattr__(self, name, value)
    else:
      setattr(self.__GetValue(), name, value)
