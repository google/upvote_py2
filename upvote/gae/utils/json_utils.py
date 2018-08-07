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


DEFAULT_DATETIME_FORMAT = '%Y-%m-%dT%H:%MZ'
EXTENDED_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


class JSONEncoder(json.JSONEncoder):
  """JSON Encoder for returning values to clients."""

  def __init__(self, datetime_format=DEFAULT_DATETIME_FORMAT, **kwargs):
    self._datetime_format = datetime_format
    super(JSONEncoder, self).__init__(**kwargs)

  def default(self, obj):
    if isinstance(obj, (set, frozenset)):
      return list(obj)
    elif isinstance(obj, datetime.datetime):
      return str(obj.strftime(self._datetime_format))
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


class JSONDecoder(json.JSONDecoder):

  def __init__(self, datetime_format=DEFAULT_DATETIME_FORMAT, **kwargs):
    defaults = {'object_hook': CreateDatetimeObjectHook(datetime_format)}
    defaults.update(kwargs.copy())
    super(JSONDecoder, self).__init__(**defaults)


def CreateDatetimeObjectHook(datetime_format):
  """Creates a JSONDecoder object hook for formatting datetime objects."""

  def _DatetimeObjectHook(old_dict):
    """JSONDecoder object hook for formatting datetime objects."""
    new_dict = {}
    for k, v in old_dict.iteritems():
      if isinstance(v, (str, unicode)):
        try:
          new_dict[k] = datetime.datetime.strptime(v, datetime_format)
        except ValueError:
          new_dict[k] = v
      else:
        new_dict[k] = v
    return new_dict

  return _DatetimeObjectHook
