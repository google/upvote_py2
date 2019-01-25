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

"""Unit tests for notify.py."""

import mock

from upvote.gae.datastore import test_utils
from upvote.gae.lib.exemption import notify
from upvote.gae.lib.testing import basetest
from upvote.shared import constants


# Done for brevity.
_STATE = constants.EXEMPTION_STATE


class SendEmailTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(SendEmailTest, self).setUp()
    self.mock_send = self.Patch(notify.mail_utils, 'Send')

  def testWindows(self):
    users = ['aaaa', 'bbbb']
    host = test_utils.CreateBit9Host(users=users)
    host_id = host.key.id()
    exm_key = test_utils.CreateExemption(host_id)
    notify._SendEmail(exm_key, 'body')
    expected_subject = 'Lockdown exemption update: %s' % host.hostname
    self.mock_send.assert_called_once_with(
        expected_subject, 'body', to=users, html=True)

  def testMacOs(self):
    host = test_utils.CreateSantaHost(primary_user='aaaa')
    host_id = host.key.id()
    exm_key = test_utils.CreateExemption(host_id)
    notify._SendEmail(exm_key, 'body')
    expected_subject = 'Lockdown exemption update: %s' % host.hostname
    self.mock_send.assert_called_once_with(
        expected_subject, 'body', to=['aaaa'], html=True)


class SendUpdateEmailTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(SendUpdateEmailTest, self).setUp()
    self.mock_send = self.Patch(notify.mail_utils, 'Send')

  def testWindows(self):
    users = ['aaaa', 'bbbb']
    host = test_utils.CreateBit9Host(users=users)
    host_id = host.key.id()
    exm_key = test_utils.CreateExemption(host_id)
    notify.SendUpdateEmail(exm_key, _STATE.APPROVED)
    expected_subject = 'Lockdown exemption update: %s' % host.hostname
    self.mock_send.assert_called_once_with(
        expected_subject, mock.ANY, to=users, html=True)

  def testMacOs(self):
    host = test_utils.CreateSantaHost(primary_user='aaaa')
    host_id = host.key.id()
    exm_key = test_utils.CreateExemption(host_id)
    notify.SendUpdateEmail(exm_key, _STATE.APPROVED)
    expected_subject = 'Lockdown exemption update: %s' % host.hostname
    self.mock_send.assert_called_once_with(
        expected_subject, mock.ANY, to=['aaaa'], html=True)


class DeferUpdateEmailTest(basetest.UpvoteTestCase):

  def testDefers(self):

    mock_send = self.Patch(notify.mail_utils, 'Send')
    host_id = test_utils.CreateSantaHost(primary_user='aaaa').key.id()
    exm_key = test_utils.CreateExemption(host_id)

    notify.DeferUpdateEmail(exm_key, _STATE.APPROVED, transactional=False)

    self.assertTaskCount(constants.TASK_QUEUE.EXEMPTIONS, 1)
    self.DrainTaskQueue(constants.TASK_QUEUE.EXEMPTIONS)
    mock_send.assert_called_once_with(
        mock.ANY, mock.ANY, to=['aaaa'], html=True)


class SendExpirationEmailTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(SendExpirationEmailTest, self).setUp()
    self.mock_send = self.Patch(notify.mail_utils, 'Send')

  def testWindows(self):
    users = ['aaaa', 'bbbb']
    host = test_utils.CreateBit9Host(users=users)
    host_id = host.key.id()
    exm_key = test_utils.CreateExemption(host_id)
    notify.SendExpirationEmail(exm_key)
    expected_subject = 'Lockdown exemption update: %s' % host.hostname
    self.mock_send.assert_called_once_with(
        expected_subject, mock.ANY, to=users, html=True)

  def testMacOs(self):
    host = test_utils.CreateSantaHost(primary_user='aaaa')
    host_id = host.key.id()
    exm_key = test_utils.CreateExemption(host_id)
    notify.SendExpirationEmail(exm_key)
    expected_subject = 'Lockdown exemption update: %s' % host.hostname
    self.mock_send.assert_called_once_with(
        expected_subject, mock.ANY, to=['aaaa'], html=True)


if __name__ == '__main__':
  basetest.main()
