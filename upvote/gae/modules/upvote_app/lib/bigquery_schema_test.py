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

"""Tests that bigquery.py and bigquery_schema.py are in sync."""

from upvote.gae.datastore.models import bigquery as bq
from upvote.gae.modules.upvote_app.lib import bigquery_schema as bqs
from upvote.gae.shared.common import basetest

from upvote.shared import constants


class BigQuerySchemaTest(basetest.UpvoteTestCase):

  def testAllSchemasDefined(self):
    """Make sure that every schema is defined in the TABLE_SCHEMAS map."""
    self.assertSameElements(
        bqs.TABLE_SCHEMAS.keys(), constants.GAE_STREAMING_TABLES.SET_ALL)

  def testSchemasInSync(self):
    model_to_schema = {
        bq.VoteRow: bqs.VOTE,
        bq.HostRow: bqs.HOST,
        bq.BinaryRow: bqs.BINARY,
        bq.ExecutionRow: bqs.EXECUTION,
        bq.CertificateRow: bqs.CERTIFICATE,
        bq.BundleRow: bqs.BUNDLE,
        bq.BundleBinaryRow: bqs.BUNDLE_BINARY,
        bq.UserRow: bqs.USER}

    for model, schema in model_to_schema.iteritems():
      model_name = model.__name__
      model_properties = set(model().to_dict().keys()) - set(['class_'])
      schema_fields = set(field.name for field in schema)

      missing_fields = model_properties - schema_fields
      missing_properties = schema_fields - model_properties

      # Check that every schema field is defined in the model.
      if missing_fields:
        self.fail(
            '%s does not contain the following schema fields" %s"' %
            (model_name, missing_fields))

      # Check that the model contains no properties not defined in schema.
      if missing_properties:
        self.fail(
            '%s contains the following properties not defined in schema: %s' %
            (model_name, missing_properties))


if __name__ == '__main__':
  basetest.main()
