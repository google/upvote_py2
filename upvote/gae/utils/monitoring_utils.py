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

"""A common monitoring interface."""

import functools
import logging


def ContainExceptions(func):

  @functools.wraps(func)
  def Wrapper(self, *args, **kwargs):
    try:
      func(self, *args, **kwargs)
    except Exception:  # pylint: disable=broad-except
      logging.exception('Monitoring error encountered')

  return Wrapper


class Metric(object):
  """Base Upvote metric."""

  def __init__(self, metric, value_type, fields=None):
    self.display_name = metric.display_name
    self.metric_name = metric.metric_name
    self.type_ = value_type
    self.fields = fields

  @ContainExceptions
  def Set(self, value, *args):
    # <Your code here>Implement setting a metric</Your code here>
    pass


class LatencyMetric(object):
  """Upvote metric for tracking latency."""

  def __init__(self, metric, fields=None):
    self.display_name = metric.display_name
    self.metric_name = metric.metric_name
    self.fields = fields

  @ContainExceptions
  def Record(self, value, *args):
    # <Your code here>Implement recording a latency value</Your code here>
    pass


class Counter(object):
  """Base Upvote counter."""

  def __init__(self, metric, fields=None):
    self.display_name = metric.display_name
    self.metric_name = metric.metric_name
    self.fields = fields

  @ContainExceptions
  def Increment(self, *args):
    # <Your code here>Implement incrementing a metric</Your code here>
    pass

  @ContainExceptions
  def IncrementBy(self, inc, *args):
    # <Your code here>Implement incrementing a metric by N</Your code here>
    pass


class RequestCounter(Counter):
  """Counts HTTP requests and their corresponding status codes."""

  def __init__(self, metric):
    fields = [(u'http_status', int)]
    super(RequestCounter, self).__init__(metric, fields=fields)


class SuccessFailureCounter(Counter):
  """Counts the success/failure rate of a given piece of code."""

  def __init__(self, metric):
    fields = [(u'outcome', str)]
    super(SuccessFailureCounter, self).__init__(metric, fields=fields)

  def Success(self):
    self.Increment('Success')

  def Failure(self):
    self.Increment('Failure')
