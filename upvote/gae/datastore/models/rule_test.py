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

"""Unit tests for rule.py."""

from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import rule
from upvote.gae.datastore.models import santa
from upvote.gae.lib.testing import basetest


class EnsureCriticalRulesTest(basetest.UpvoteTestCase):

  def testSuccess(self):

    self.assertEntityCount(santa.SantaCertificate, 0)
    self.assertEntityCount(santa.SantaRule, 0)

    sha256_list = [test_utils.RandomSHA256() for _ in xrange(5)]
    rule.EnsureCriticalRules(sha256_list)

    self.assertEntityCount(santa.SantaCertificate, 5)
    self.assertEntityCount(santa.SantaRule, 5)


if __name__ == '__main__':
  basetest.main()
