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

"""Constants for the Bit9 API."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

__all__ = ['METHOD', 'VERSION']


class METHOD(object):
  GET = 'GET'
  POST = 'POST'
  PUT = 'PUT'
  DELETE = 'DELETE'

  SET_ALL = frozenset([GET, POST, PUT, DELETE])


class VERSION(object):
  V1 = 'v1'

  SET_ALL = frozenset([V1])
