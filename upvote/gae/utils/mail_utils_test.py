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

"""Unit tests for mail_utils.py."""

from upvote.gae.lib.testing import basetest
from upvote.gae.utils import mail_utils
from upvote.gae.utils import user_utils


class SanitizeAddrsTest(basetest.UpvoteTestCase):

  def testList_Username(self):
    expected = [user_utils.UsernameToEmail('aaa')]
    actual = mail_utils._SanitizeAddrs(['aaa'])
    self.assertListEqual(expected, actual)

  def testList_Email(self):
    expected = [user_utils.UsernameToEmail('aaa')]
    actual = mail_utils._SanitizeAddrs([user_utils.UsernameToEmail('aaa')])
    self.assertListEqual(expected, actual)

  def testList_Whitespace(self):
    expected = [user_utils.UsernameToEmail('aaa')]
    actual = mail_utils._SanitizeAddrs(['  aaa  '])
    self.assertListEqual(expected, actual)

  def testStr_Username(self):
    expected = [user_utils.UsernameToEmail('aaa')]
    actual = mail_utils._SanitizeAddrs('aaa')
    self.assertEqual(expected, actual)

  def testStr_Email(self):
    expected = [user_utils.UsernameToEmail('aaa')]
    actual = mail_utils._SanitizeAddrs(user_utils.UsernameToEmail('aaa'))
    self.assertEqual(expected, actual)

  def testStr_Whitespace(self):
    expected = [user_utils.UsernameToEmail('aaa')]
    actual = mail_utils._SanitizeAddrs('  aaa  ')
    self.assertEqual(expected, actual)

  def testUnknown(self):
    for unsupported in [{}, None, 12345]:
      self.assertEqual([], mail_utils._SanitizeAddrs(unsupported))


class SendTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(SendTest, self).setUp()
    self.mock_send = self.Patch(mail_utils.mail.EmailMessage, 'send')

  def testNoRecipientsError(self):
    with self.assertRaises(mail_utils.NoRecipientsError):
      mail_utils.Send('subject', 'body')
    self.mock_send.assert_not_called()

  def testCheckInitializedException(self):
    self.Patch(
        mail_utils.mail.EmailMessage, 'check_initialized',
        side_effect=Exception)
    mail_utils.Send('subject', 'body', to='to')
    self.mock_send.assert_not_called()

  def testSuccess(self):
    mail_utils.Send('subject', 'body', to='to')
    self.mock_send.assert_called_once()


if __name__ == '__main__':
  basetest.main()
