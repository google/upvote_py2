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

from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import package as package_models
from upvote.gae.lib.testing import basetest
from upvote.shared import constants


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

  def testIsInstance(self):
    bundle = test_utils.CreateSantaBundle()
    self.assertTrue(bundle.IsInstance('Blockable'))
    self.assertTrue(bundle.IsInstance('Package'))
    self.assertTrue(bundle.IsInstance('SantaBundle'))
    self.assertFalse(bundle.IsInstance('SomethingElse'))

  def testIgnoreCalculateScoreBeforeUpload(self):
    bundle = test_utils.CreateSantaBundle(uploaded_dt=None)
    test_utils.CreateVote(bundle)

    # Trigger the SantaBundle.score ComputedProperty calculation.
    bundle.put()

    # The score should have not reflected the real score until the bundle is
    # uploaded.
    self.assertEqual(0, bundle.key.get().score)

  def testToDict(self):
    bundle = test_utils.CreateSantaBundle()
    with self.LoggedInUser():
      dict_ = bundle.to_dict()
    self.assertTrue(dict_['has_been_uploaded'])
    self.assertIsNone(dict_['cert_id'])

  def testToDict_CertId(self):
    santa_certificate = test_utils.CreateSantaCertificate()
    blockable = test_utils.CreateSantaBlockable(cert_key=santa_certificate.key)
    bundle = test_utils.CreateSantaBundle(
        main_cert_key=santa_certificate.key,
        bundle_binaries=[blockable])
    with self.LoggedInUser():
      dict_ = bundle.to_dict()
    self.assertTrue(dict_['has_been_uploaded'])
    self.assertEqual(santa_certificate.key.id(), dict_['cert_id'])

  def testPersistsStateChange(self):
    bundle = test_utils.CreateSantaBundle(uploaded_dt=None)
    bundle.ChangeState(constants.STATE.SUSPECT)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.BUNDLE)

  def testResetsState(self):
    bundle = test_utils.CreateSantaBundle(uploaded_dt=None)
    bundle.ResetState()
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.BUNDLE)


if __name__ == '__main__':
  basetest.main()
