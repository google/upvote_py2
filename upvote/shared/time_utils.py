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

"""Time-related utility methods."""

import datetime

from upvote.gae.modules.bit9_api import constants as bit9_constants


def Now():
  return datetime.datetime.utcnow()


def TimeRemains(start_time, duration):
  """Used for constraining loops based on time rather than number of loops.

  Args:
    start_time: The starting datetime of execution.
    duration: A datetime.timedelta indication the execution duration.

  Returns:
    True if execution should continue, False otherwise.
  """
  return start_time + duration > Now()


def DatetimeToInt(dt):
  """Converts a datetime object to an integer number of seconds since epoch.

  Args:
    dt: The datetime object to convert.

  Returns:
    The integer number of seconds since epoch.
  """
  epoch = datetime.datetime.utcfromtimestamp(0)
  return int((dt - epoch).total_seconds())


def IntToDatetime(i):
  """Converts an integer number of seconds since epoch to a datetime object.

  Args:
    i: The integer number of seconds to convert.

  Returns:
    A representative datetime object.
  """
  return datetime.datetime.utcfromtimestamp(i)


