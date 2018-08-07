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

"""Unit tests for routes.py."""

from upvote.gae.lib.testing import basetest
from upvote.gae.modules.bit9_api import main


class MainTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(MainTest, self).setUp(wsgi_app=main.app)

  def testRoutes(self):
    self.assertRoutesDefined(
        '/_ah/warmup',

        '/api/bit9/ack',

        '/api/bit9/cron/commit-pending-change-sets',
        '/api/bit9/cron/update-policies',
        '/api/bit9/cron/count-events-to-pull',
        '/api/bit9/cron/pull-events',
        '/api/bit9/cron/count-events-to-process',
        '/api/bit9/cron/process-events')


if __name__ == '__main__':
  basetest.main()
