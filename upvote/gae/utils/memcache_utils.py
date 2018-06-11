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

"""Cache operations."""

import functools

from common import memcache_decorator


def ConditionallyCached(cache_predicate=lambda *a: True, **kwargs):
  """Decorator that caches a subset of a function's results.

  Extends memcache_decorator.Cached to allow certain invocations to not be
  cached.

  Args:
    cache_predicate: func(list, dict, Any), A function that accepts the args
        list and kwargs dict that the wrapped function was called with as well
        as the wrapped function's return value. If the predicate returns True,
        the invocation will be cached. Otherwise, no cache entry will be
        recorded.
        If not supplied, result is always cached.
    **kwargs: Keyword args to be passed to Cached.

  Returns:
    The decorator described above
  """
  cache_decorator = memcache_decorator.Cached(**kwargs)

  def Decorator(func):
    """Decorator to cache a function's results."""

    # First, decorate the function with Cached.
    decorated = cache_decorator(func)

    # Then, decorate it with the conditional cache logic.
    @functools.wraps(decorated)
    def Wrapped(*args, **kwargs):
      result = decorated(*args, **kwargs)
      if not cache_predicate(args, kwargs, result):
        decorated.DeleteCache(*args, **kwargs)
      return result

    return Wrapped

  return Decorator
