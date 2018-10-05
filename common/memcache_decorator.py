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

"""A decorator to quickly use memcache on any function."""

import functools
import hashlib
import pickle

from google.appengine.api import memcache

from common import context


def DefaultCreateKey(func, prefix, args, kwargs=None):
  """Creates a key name from prefix, function name, args and kwargs.

  Args:
    func: function - the function that is decorated.
    prefix: str - the optional key prefix that was passed to the decorator.
    args: list of * - the arguments that were used to call the function.
    kwargs: dict - the keyword arguments that were used to call the function.
  Returns:
    str - the string to use as key in memcache.
  """
  module = func.__module__ or 'None'
  key = prefix or module + '.' + func.__name__
  if args:
    for arg in args:
      try:
        key += pickle.dumps(arg)
      except pickle.PicklingError:
        key += _ToShortStr(arg)
  if kwargs:
    key += pickle.dumps(kwargs)
  return hashlib.md5(key).hexdigest()


def Cached(
    key_name=None, expire_time=0, create_key_func=DefaultCreateKey,
    namespace=context.APP_VERSION):
  """Decorator function to cache (using memcache API) a function's results.

  This decorator won't work in all cases and you should pay attention on how you
  use it:
   - it creates a key for each different call by converting arguments into
     string, using pickle, and then taking the md5 of the key string.
   - you can provide your own create_key_func. The keys can collide if
     create_key_func generates the same key for different arguments.
   - you can use it for classmethods, you can't use it for methods.

  Use DeleteCache on the function using the same argument to delete the cache
  for this value. See DeleteCache documentation.

  Args:
    key_name: str - the prefix of the memcache key to use, default is to use the
        functions's name.
    expire_time: int - Optional expiration time, either relative number of
        seconds from current time (up to 1 month), or an absolute Unix epoch
        time.  By default, items never expire, though items may be evicted due
        to memory pressure. Float values will be rounded up to the nearest whole
        second.
    create_key_func: function - Functions used to generate the memcache key
        where the result of each call will be cached. See _DefaultCreateKey for
        the signature. _DefaultCreateKey is also the default parameter.
    namespace: str - the memcache namespace to use.
  Returns:
    A decorator.
  """

  def Decorator(func):
    """Decorator to cache a function's results.

    Args:
      func: function - function to cache.
    Returns:
      function - the wrapped function.
    """

    @functools.wraps(func)
    def Wrapped(*args, **kwargs):
      key = create_key_func(func, key_name, args, kwargs)
      result = memcache.get(key, namespace=namespace)
      if result is not None:
        return result
      result = func(*args, **kwargs)
      # Cast expire_time to int so lazy's are resolved and accepted in memcache.
      memcache.set(key, result, time=int(expire_time), namespace=namespace)
      return result

    def DeleteCache(*args, **kwargs):
      """Delete cache for *args.

      Args:
        *args: Decorated function args for which to clear the cache.
        **kwargs: Decorated function keyword args for which to clear the cache.
      Usage:
        @memcache_decorator.cached()
        def MyFunc(arg1):
           return arg1

        MyFunc('a')
        MyFunc('a')  // returns cached result
        MyFunc.DeleteCache('a')  // Delete the cache for 'a'.
      """
      memcache.delete(create_key_func(func, key_name, args, kwargs),
                      namespace=namespace)

    Wrapped.DeleteCache = DeleteCache

    return Wrapped

  return Decorator


def _ToShortStr(arg):
  """Gets a short string representation of an object."""
  if hasattr(arg, '__name__'):
    return arg.__name__
  return str(arg)
