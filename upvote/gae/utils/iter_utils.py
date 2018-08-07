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

"""Iterator-related utility methods."""

import itertools


def Grouper(iterable, chunk_size, fillvalue=None):
  """Chunks an iterable.

  Source: http://docs.python.org/library/itertools.html.

  Args:
    iterable: iterable, An iterable.
    chunk_size: int, Chunk size.
    fillvalue: object, Fill value.

  Returns:
    An iterable of chunks.
  """
  args = [iter(iterable)] * chunk_size
  return itertools.izip_longest(*args, fillvalue=fillvalue)
