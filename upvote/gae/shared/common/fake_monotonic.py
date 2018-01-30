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

"""A Pure Python replacement for the monotonic library.

`google-cloud-core` depends on `tenacity` which depends on `monotonic`, a native
backport of the Python 3's `time.monotonic` function. Since `monotonic` depends
on ctypes and App Engine's Standard Environment does not support ctypes, a
workaround is necessary to replace its behavior.

Functionally, time.monotonic just provides a timer guaranteed not to tick
backwards (as the term "monotonic" implies). We can duplicate this behavior by
wrapping the normal time.time method with a small bit of logic and state that
ensure the returned tick is greater than or equal to the previous tick.
"""
import time

_LAST_TICK = time.time()


def monotonic():
  global _LAST_TICK
  _LAST_TICK = max(_LAST_TICK, time.time())
  return _LAST_TICK
