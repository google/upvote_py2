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

# Lint as: python2, python3
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import mock
import six

from google.appengine.ext import db
from google.appengine.ext import ndb
from common.testing import basetest
from common.cloud_kms import cloud_kms
from upvote.gae.datastore.models import kms


class EncryptedBlobPropertyTest(basetest.AppEngineTestCase):

  @mock.patch.object(
      cloud_kms, 'Decrypt',
      side_effect=lambda data, a2, a3, **kwargs: data)
  @mock.patch.object(
      cloud_kms,
      'Encrypt',
      side_effect=lambda data, a2, a3, **kwargs: six.text_type(data))
  def testCorrectKey(self, encrypt_mock, decrypt_mock):
    class Foo(ndb.Model):
      foo = kms.EncryptedBlobProperty('a', 'b', 'c')

    key = Foo(foo='abcd').put()
    encrypt_mock.assert_called_once_with('abcd', 'a', 'b', key_location='c')

    self.assertEqual('abcd', key.get().foo)
    decrypt_mock.assert_called_with('abcd', 'a', 'b', key_location='c')

  def testOtherProperties(self):
    class Foo(ndb.Model):
      foo = kms.EncryptedBlobProperty('a', 'b', 'c', required=True)

    with self.assertRaises(db.BadValueError):
      Foo().put()


if __name__ == '__main__':
  basetest.main()
