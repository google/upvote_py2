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

"""Module for interacting with the Bit9 REST API ORM."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from upvote.gae.modules.bit9_api.api import exceptions as excs


class FilterNode(object):
  """A query node used to filter property values using arbitrary operators."""

  def __init__(self, prop, operator, value=None):
    self.prop = prop
    self.operator = operator
    self.value = value if value is not None else ''

  def __or__(self, other):
    if hash(self.prop) != hash(other.prop):
      raise excs.QueryError(
          '{!r} cannot be combined with {!r}'.format(self.prop, other.prop))
    elif self.operator != other.operator:
      raise excs.QueryError(
          'Operator mismatch with {!r} filter.'
          ' Use two separate filter calls.'.format(self.prop))
    new_value = '|'.join((self.value, other.value))
    return FilterNode(self.prop, self.operator, new_value)

  def __repr__(self):
    return '{}{}{}'.format(self.prop.name, self.operator, self.value)


class OrderNode(object):

  def __init__(self, prop, ascending=True):
    self.prop = prop
    self.ascending = ascending

  def __repr__(self):
    return '{} {}'.format(self.prop.name, 'ASC' if self.ascending else 'DESC')
