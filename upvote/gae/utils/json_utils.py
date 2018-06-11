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

"""JSON utilities for Upvote."""

import datetime
import json
import re

from google.appengine.ext import ndb


class JSONEncoder(json.JSONEncoder):
  """JSON Encoder for returning values to clients."""

  def default(self, obj):
    if isinstance(obj, (set, frozenset)):
      return list(obj)
    elif isinstance(obj, datetime.datetime):
      return str(obj.strftime('%Y-%m-%dT%H:%MZ'))
    elif isinstance(obj, (datetime.date, datetime.time)):
      return str(obj)
    elif isinstance(obj, ndb.Key):
      return obj.urlsafe()
    elif hasattr(obj, 'to_dict'):
      return obj.to_dict()
    else:
      return super(JSONEncoder, self).default(obj)


class JSONEncoderJavaScript(JSONEncoder):
  """JSON Encoder for returning values to JavaScript clients."""

  CAMEL_RE = re.compile(r'_([a-z])')

  def iterencode(self, *args, **kwargs):
    parts = super(JSONEncoderJavaScript, self).iterencode(*args, **kwargs)
    prev_part, parts = parts[0], parts[1:]
    for part in parts:
      if part == ':' or part == ': ':
        prev_part = self.CAMEL_RE.sub(lambda x: x.group(1).upper(), prev_part)
      yield prev_part
      prev_part = part
    yield prev_part
