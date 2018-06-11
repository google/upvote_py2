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

"""Model for persisting user-facing messages (degradation, outages, etc)."""

from google.appengine.ext import ndb

from upvote.shared import constants


class Alert(ndb.Model):
  """User-facing alert.

  Attributes:
    message: The basic message to be displayed to the user.
    details: Optional extra details that the user can reveal.
    start_date: Time when the alert should become visible.
    end_date: Optional time when the alert should expire.
    platform: Platform which will restrict where the message is displayed.
    scope: Location(s) where the message should be displayed.
    severity: Severity of the message to be displayed.
  """
  message = ndb.StringProperty(required=True)
  details = ndb.StringProperty()
  start_date = ndb.DateTimeProperty(required=True)
  end_date = ndb.DateTimeProperty()
  platform = ndb.StringProperty(
      required=True, choices=constants.SITE_ALERT_PLATFORM.SET_ALL)
  scope = ndb.StringProperty(
      required=True, choices=constants.SITE_ALERT_SCOPE.SET_ALL)
  severity = ndb.StringProperty(
      required=True, choices=constants.SITE_ALERT_SEVERITY.SET_ALL)

  @classmethod
  def New(cls, scope=None, platform=None, **kwargs):
    parent_id = ('%s_%s' % (scope, platform)).lower()
    parent_key = ndb.Key(cls, parent_id)
    return cls(parent=parent_key, scope=scope, platform=platform, **kwargs)

  @classmethod
  def Insert(cls, **kwargs):
    return cls.New(**kwargs).put()
