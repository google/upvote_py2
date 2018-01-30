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

"""Unit tests for user_map.py."""

from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import settings
from upvote.gae.shared.common import user_map


class UtilsTests(basetest.UpvoteTestCase):

  def testEmailToUsername(self):
    self.assertEqual('user', user_map.EmailToUsername('user@foo.com'))
    self.assertEqual('user', user_map.EmailToUsername('user'))

  def testUsernameToEmail(self):
    self.assertEqual(
        'user@' + settings.USER_EMAIL_DOMAIN, user_map.UsernameToEmail('user'))


if __name__ == '__main__':
  basetest.main()
