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

"""A simple key-value cache."""

from google.appengine.ext import ndb


class KeyValueCache(ndb.Model):
  """Data cached that doesn't require a separate model.

  Attributes:
    recorded_dt: DateTime, time of insertion.
    value: Text, value inserted.
  """
  recorded_dt = ndb.DateTimeProperty(auto_now_add=True)
  value = ndb.JsonProperty()
