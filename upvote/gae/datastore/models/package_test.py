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

"""Unit tests for package.py."""

from google.appengine.ext import ndb

from upvote.gae.datastore.models import package as package_models
from upvote.gae.lib.testing import basetest


class SantaBundleTest(basetest.UpvoteTestCase):

  def testTranslatePropertyQuery_CertId(self):
    field, val = 'cert_id', 'bar'

    new_field, new_val = package_models.SantaBundle.TranslatePropertyQuery(
        field, val)

    self.assertEqual(val, ndb.Key(urlsafe=new_val).id())
    self.assertEqual('main_cert_key', new_field)

  def testTranslatePropertyQuery_CertId_NoQueryValue(self):
    field, val = 'cert_id', None

    new_field, new_val = package_models.SantaBundle.TranslatePropertyQuery(
        field, val)

    self.assertIsNone(new_val)
    self.assertEqual('main_cert_key', new_field)

  def testTranslatePropertyQuery_NotCertId(self):
    pair = ('foo', 'bar')
    self.assertEqual(
        pair, package_models.SantaBundle.TranslatePropertyQuery(*pair))


if __name__ == '__main__':
  basetest.main()
