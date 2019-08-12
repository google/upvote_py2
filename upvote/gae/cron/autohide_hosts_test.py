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

"""Unit tests for autohide_hosts.py."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import datetime

import six.moves.http_client
import webapp2

from upvote.gae import settings
from upvote.gae.cron import autohide_hosts
from upvote.gae.datastore import test_utils
from upvote.gae.lib.testing import basetest
from upvote.shared import constants


class AutohideSantaHostTest(basetest.UpvoteTestCase):

  def testHide(self):

    host = test_utils.CreateSantaHost(hidden=False)
    self.assertFalse(host.hidden)

    host_key = host.key
    autohide_hosts._AutohideSantaHost(host_key)
    host = host_key.get()
    self.assertTrue(host.hidden)


class AutohideSantaHostsTest(basetest.UpvoteTestCase):

  def testDefer(self):

    active_dt = datetime.datetime.utcnow()
    inactive_dt = datetime.datetime.utcnow() - datetime.timedelta(
        days=settings.HOST_INACTIVITY_THRESHOLD + 1)

    # Create a mix of SantaHosts, with all combinations of inactivity and
    # hidden-ness.
    test_utils.CreateSantaHosts(3, hidden=True, last_postflight_dt=active_dt)
    test_utils.CreateSantaHosts(5, hidden=False, last_postflight_dt=active_dt)
    test_utils.CreateSantaHosts(7, hidden=True, last_postflight_dt=inactive_dt)
    test_utils.CreateSantaHosts(9, hidden=False, last_postflight_dt=inactive_dt)

    autohide_hosts._AutohideSantaHosts()
    self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 9)


class AutohideHostsTest(basetest.UpvoteTestCase):

  ROUTE = '/hosts/autohide'

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[autohide_hosts.ROUTES])
    super(AutohideHostsTest, self).setUp(wsgi_app=app)

  def testDefer(self):
    self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 0)
    self.testapp.get(
        self.ROUTE,
        headers={'X-AppEngine-Cron': 'true'},
        status=six.moves.http_client.OK)
    self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 1)


if __name__ == '__main__':
  basetest.main()
