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

"""Implementation of simple lock using datastore.

These locks rely on datastore's optimistic concurrency control to ensure
atomicity and support the semantics of a basic threading.Lock object.

This library differs from memcache_locks in that it guarantees the persistence
of locks and of mutual exclusion. It also offers an async api.
"""

import datetime
import logging
import uuid

from google.appengine.api import datastore_errors
from google.appengine.ext import ndb



_DATASTORE_LOCK_TYPE = u'ApphostingContribDatastoreLock2'
_INITIAL_DELAY = .3
_USE_DEFAULT_TIMEOUT = object()  # Sentinel for using default timeout.


class Error(Exception):
  """Base class for all errors raised from this module."""


class AcquireLockError(Error):
  """Raised on error acquiring lock."""


class RefreshLockError(Error):
  """Raised on error refreshing lock."""


class ReleaseLockError(Error):
  """Raised on error releasing lock."""


class _DatastoreLockEntity(ndb.Model):
  timeout = ndb.IntegerProperty()
  acquired_at = ndb.DateTimeProperty(auto_now=True)
  acquired = ndb.BooleanProperty(default=False)
  lock_id = ndb.StringProperty()

  @classmethod
  def _get_kind(cls):
    return _DATASTORE_LOCK_TYPE

  @property
  def lock_held(self):
    """Whether the lock is acquired and not orphaned."""
    return self.acquired and (not self.timeout or
                              ((datetime.datetime.utcnow() - self.acquired_at)
                               <= datetime.timedelta(seconds=self.timeout)))


_LOCK_DEFAULT_TIMEOUT = 60
_LOCK_DEFAULT_MAX_ACQUIRE_ATTEMPTS = 20


class DatastoreLock(object):
  """Implementation of basic (non-reentrant) lock using datastore.

  Like MemcacheLock, this lock supports a timeout, after which the lock will be
  considered "orphaned" and may be acquired. Once a lock is orphaned, all
  methods on the original lock object (like Release) will result in undefined
  behavior. As a result, it is good practice to set the timeout to greater than
  the life of the HTTP request using the lock, so as to guarantee the original
  lock holder will never use the lock after it is orphaned.

  This lock offers asynchronous versions of Acquire and Release that should be
  used in ndb tasklets in place of Acquire, Release, and context manager api.

  Attributes:
    _lock_id: A unique id for the lock, automatically generated on acquire. This
      id is separate from the lock's primary identifier, and should be used to
      verify ownership of the lock.
    default_timeout: Default timeout in seconds for how long this lock will
      be held if not explicitly released.
    default_max_acquire_attempts: Default maximum number of attempts allowed to
      acquire the lock.
  """

  _use_cache = False
  _use_memcache = False

  def __init__(
      self, id_, default_timeout=_LOCK_DEFAULT_TIMEOUT,
      default_max_acquire_attempts=_LOCK_DEFAULT_MAX_ACQUIRE_ATTEMPTS):
    """Init for DatastoreLock.

    Args:
      id_: The ID of the lock entity stored in ndb.
      default_timeout: Timeout in seconds for ths lock, used when 'timeout' is
        not provided in the Acquire method. If set to None and the lock holder
        dies before releasing the lock, it will be in a perpetual acquired
        state.
      default_max_acquire_attempts: Maximum number of attempts for acquiring the
        lock, used when 'max_acquire_attempts' is not provided in the Acquire
        method.
    Raises:
      ValueError: If default_max_acquire_attempts < 1.
    """
    if default_max_acquire_attempts < 1:
      raise ValueError(u'default_max_acquire_attempts must be >= 1')

    self._id = id_
    self._acquired = False
    self._lock_id = None
    self.default_timeout = default_timeout
    self.default_max_acquire_attempts = default_max_acquire_attempts

  def __getstate__(self):
    return {
        '_id': self._id,
        '_acquired': self._acquired,
        '_lock_id': self._lock_id,
        'default_timeout': self.default_timeout,
        'default_max_acquire_attempts': self.default_max_acquire_attempts,
    }

  def __setstate__(self, state):
    # NOTE: When changing format, be sure to add a test
    # to confirm old pickle objects can be deserialized and unlocked.
    # e.g. testLoadOldPickledLockAfterNewCodeRelease
    self._id = state['_id']
    self._acquired = state['_acquired']
    self._lock_id = state['_lock_id']
    if 'default_timeout' in state:
      self.default_timeout = state['default_timeout']
    else:
      self.default_timeout = _LOCK_DEFAULT_TIMEOUT
    if 'default_max_acquire_attempts' in state:
      self.default_max_acquire_attempts = state['default_max_acquire_attempts']
    else:
      self.default_max_acquire_attempts = _LOCK_DEFAULT_MAX_ACQUIRE_ATTEMPTS

  @ndb.tasklet
  def AcquireAsync(self,
                   blocking=True,
                   max_acquire_attempts=None,
                   timeout=_USE_DEFAULT_TIMEOUT):
    """Acquires a lock asynchronously, blocking or non-blocking.

    If non-blocking, a single attempt will be made to acquire the lock;
    otherwise, max_acquire_attempts will be made.

    Args:
      blocking: Whether to block waiting for the lock.
      max_acquire_attempts: Maximum number of attempts to make in order to
        acquire the lock if blocking. If None, default_max_acquire_attempts
        will be used instead.
      timeout: Optional timeout for the lock in seconds, after which it will be
        assumed to be free (even if never explicitly released). Defaults to the
        timeout value set during initialization. If this value is set to None
        and the lock holder dies before releasing the lock, it will be in a
        perpetual acquired state.
    Returns:
      True if the lock was acquired, or False if the lock was not acquired and
      blocking=False.
    Raises:
      AcquireLockError: If the lock is already acquired via this lock object,
        or if max_acquire_attempts is exceeded.
      ValueError: If max_acquire_attempts < 1.
    """
    if self._acquired:
      raise AcquireLockError(u'Lock already acquired')

    if max_acquire_attempts is None:
      max_acquire_attempts = self.default_max_acquire_attempts

    if max_acquire_attempts < 1:
      raise ValueError(u'max_acquire_attempts must be >= 1')

    if timeout is _USE_DEFAULT_TIMEOUT:
      timeout = self.default_timeout

    self._lock_id = str(uuid.uuid4())
    self._acquired = yield self._AcquireAsync(timeout)

    if self._acquired:
      raise ndb.Return(True)
    elif not blocking:
      raise ndb.Return(False)

    intervals = [_INITIAL_DELAY + i for i in xrange(max_acquire_attempts - 1)]
    for sleep_time in intervals:
      yield ndb.sleep(sleep_time)
      self._acquired = yield self._AcquireAsync(timeout)
      if self._acquired:
        raise ndb.Return(True)

    raise AcquireLockError(
        u'Failed to acquire lock [{}] after {} tries.'.format(
            self._id, max_acquire_attempts))

  @ndb.tasklet
  def ReacquireAsync(self, lock_id):
    """Asynchronously reacquires the lock.

    Lock reacquisition should be intentional. An example use case is that a lock
    is acquired in an API endpoint and then reacquired and released in
    a backend process, with the endpoint passing the lock_id and id to the
    backend process.

    Args:
      lock_id: The lock_id attribute of the original lock. Note that lock_id is
        different from the id used to create the lock.
    Returns:
      True iff the lock was reacquired.
    Raises:
      AcquireLockError: If the lock owner tries to reacquire it again.
    """
    if self._acquired:
      raise AcquireLockError(u'Lock already acquired')
    self._lock_id = lock_id
    self._acquired = yield self._ReacquireAsync()
    raise ndb.Return(self._acquired)

  def RefreshAsync(self, timeout=_USE_DEFAULT_TIMEOUT):
    """Asynchronously refreshes the lock by resetting timeout.

    Args:
      timeout: Same as the timeout argument in AcquireAsync method.
    Returns:
      True iff the lock was successfully refreshed.
    Raises:
      RefreshLockError: If the lock was never acquired.
    """
    if timeout is _USE_DEFAULT_TIMEOUT:
      timeout = self.default_timeout

    if not self._acquired:
      raise RefreshLockError(u'Lock [{}] never acquired'.format(self._id))
    return self._RefreshAsync(timeout)

  @ndb.tasklet
  def ReleaseAsync(self):
    """Releases the held lock asynchronously.

    Returns:
      True iff the lock was successfully released. The lock may not be
        successfully released if it has timed out and was subsequently acquired
        by another user.
    Raises:
      ReleaseLockError: If the lock was never acquired.
    """
    if not self._acquired:
      raise ReleaseLockError(u'Lock [{}] never acquired'.format(self._id))
    status = yield self._ReleaseAsync()
    self._acquired = False
    self._lock_id = None
    raise ndb.Return(status)

  def Acquire(self, *args, **kwargs):
    """Synchronous version of AcquireAsync."""
    return self.AcquireAsync(*args, **kwargs).get_result()

  def Reacquire(self, *args, **kwargs):
    """Synchronous version of ReacquireAsync."""
    return self.ReacquireAsync(*args, **kwargs).get_result()

  def Refresh(self, *args, **kwargs):
    """Synchronous version of RefreshAsync."""
    return self.RefreshAsync(*args, **kwargs).get_result()

  def Release(self, *args, **kwargs):
    """Synchronous version of ReleaseAsync."""
    return self.ReleaseAsync(*args, **kwargs).get_result()

  @ndb.tasklet
  def _AcquireAsync(self, timeout):
    """Acquires the lock via datastore or returns False."""

    @ndb.transactional_tasklet(retries=0)
    def _TransactionalAcquireAsync():
      lock_entity = yield _DatastoreLockEntity.get_or_insert_async(self._id)
      if lock_entity.lock_held:
        raise ndb.Return(False)

      lock_entity.lock_id = self._lock_id
      lock_entity.acquired = True
      lock_entity.timeout = timeout
      yield lock_entity.put_async()
      raise ndb.Return(True)

    try:
      raise ndb.Return((yield _TransactionalAcquireAsync()))
    except datastore_errors.Error:
      raise ndb.Return(False)

  @ndb.tasklet
  def _ReacquireAsync(self):
    lock_entity = yield _DatastoreLockEntity.get_by_id_async(self._id)

    if lock_entity.lock_id != self._lock_id:
      logging.warning(u'Invalid lock ID detected when reacquiring the '
                      u'lock [%s]', self._id)
      raise ndb.Return(False)
    raise ndb.Return(True)

  @ndb.transactional_tasklet
  def _RefreshAsync(self, timeout):
    """Refreshes the lock via datastore."""
    lock_entity = yield _DatastoreLockEntity.get_by_id_async(self._id)

    if lock_entity.lock_id != self._lock_id:
      logging.warning(u'Invalid lock ID detected when refreshing the '
                      u'lock [%s]', self._id)
      raise ndb.Return(False)
    lock_entity.timeout = timeout
    yield lock_entity.put_async()  # This also resets acquired_at.
    raise ndb.Return(True)

  @ndb.transactional_tasklet(retries=10)
  def _ReleaseAsync(self):
    lock_entity = yield _DatastoreLockEntity.get_by_id_async(self._id)

    if lock_entity.lock_id != self._lock_id:
      logging.warning('lock acquired by someone else')
      raise ndb.Return(False)
    lock_entity.acquired = False
    yield lock_entity.put_async()
    raise ndb.Return(True)

  # Add pep-8 aliases and allow lock to be used as context manager.
  acquire_async = AcquireAsync
  reacquire_async = ReacquireAsync
  refresh_async = RefreshAsync
  release_async = ReleaseAsync
  acquire = Acquire
  reacquire = Reacquire
  refresh = Refresh
  release = Release
  __enter__ = Acquire

  def __exit__(self, *unused_args):
    self.Release()
