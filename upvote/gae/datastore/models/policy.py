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

"""Models for tracking Upvote client policies."""

from google.appengine.ext import ndb

from upvote.gae.datastore.models import mixin
from upvote.shared import constants


class Bit9Policy(mixin.Bit9, ndb.Model):
  """A Host policy in Bit9.

  Corresponds to Bit9's "policy" object.

  key = The **string** id of the Bit9 policy object

  Attributes:
    name: str, The name of the policy.
    enforcement_level: BIT9_ENFORCEMENT_LEVEL, The 'target enforcement level'
        (i.e. strictness) associated with the policy. More restrictive policies
        have 'higher' enforcement levels.
    updated_dt: datetime, The time the policy was modified last.
  """
  name = ndb.StringProperty()
  enforcement_level = ndb.StringProperty(
      choices=constants.BIT9_ENFORCEMENT_LEVEL.SET_ALL)
  updated_dt = ndb.DateTimeProperty(auto_now=True)
