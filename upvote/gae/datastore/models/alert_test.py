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

"""Tests for alert models."""

import datetime

from upvote.gae.datastore.models import alert
from upvote.gae.shared.common import basetest

from upvote.shared import constants


class AlertTest(basetest.UpvoteTestCase):

  def testInsert(self):

    start_date = datetime.datetime.utcnow()
    end_date = start_date + datetime.timedelta(hours=1)

    self.assertEntityCount(alert.Alert, 0)

    key = alert.Alert.Insert(
        message='message', details='details', start_date=start_date,
        end_date=end_date, platform=constants.SITE_ALERT_PLATFORM.MACOS,
        scope=constants.SITE_ALERT_SCOPE.APPDETAIL,
        severity=constants.SITE_ALERT_SEVERITY.INFO)

    self.assertEntityCount(alert.Alert, 1)

    self.assertEqual('appdetail_macos', key.parent().id())


if __name__ == '__main__':
  basetest.main()
