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

"""Unit tests for tables.py."""

import datetime
import mock

from google.appengine.ext import ndb

from upvote.gae.bigquery import tables
from upvote.gae.datastore.models import bigquery
from upvote.gae.shared.common import basetest


TEST_TABLE = tables.BigQueryTable(
    'Test', [
        tables.Column(
            name='aaa',
            field_type=tables.FIELD_TYPE.BOOLEAN,
            mode=tables.MODE.REQUIRED),
        tables.Column(
            name='bbb',
            field_type=tables.FIELD_TYPE.INTEGER,
            mode=tables.MODE.REQUIRED),
        tables.Column(
            name='ccc',
            field_type=tables.FIELD_TYPE.STRING,
            mode=tables.MODE.REPEATED),
        tables.Column(
            name='ddd',
            field_type=tables.FIELD_TYPE.TIMESTAMP,
            mode=tables.MODE.NULLABLE),
    ])


class BigQueryTableTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(BigQueryTableTest, self).setUp()

    self.mock_client = mock.Mock(spec=tables.bigquery.Client)
    self.Patch(tables.bigquery, 'Client', return_value=self.mock_client)

    self.Patch(tables.monitoring, 'row_insertions')

  def testValidateInsertion_UnexpectedColumn(self):
    with self.assertRaises(tables.UnexpectedColumn):
      TEST_TABLE._ValidateInsertion(aaa=True, bbb=4, eee='OMG')

  def testValidateInsertion_MissingColumn(self):
    with self.assertRaises(tables.MissingColumn):
      TEST_TABLE._ValidateInsertion(aaa=True)

  def testValidateInsertion_UnexpectedNull(self):
    with self.assertRaises(tables.UnexpectedNull):
      TEST_TABLE._ValidateInsertion(aaa=True, bbb=None)

  def testValidateInsertion_InvalidRepeated(self):
    with self.assertRaises(tables.InvalidRepeated):
      TEST_TABLE._ValidateInsertion(aaa=True, bbb=4, ccc=5)

  def testValidateInsertion_InvalidType_Required(self):
    with self.assertRaises(tables.InvalidType):
      TEST_TABLE._ValidateInsertion(aaa='blah', bbb=4)

  def testValidateInsertion_InvalidType_Repeated(self):
    with self.assertRaises(tables.InvalidType):
      TEST_TABLE._ValidateInsertion(aaa=True, bbb=4, ccc=[1, 2, 3, 4])

  def testValidateInsertion_Success(self):
    now = datetime.datetime.utcnow()
    TEST_TABLE._ValidateInsertion(aaa=True, bbb=4, ccc=['ccc'], ddd=now)

  def testCreateInsertionID_Identical(self):

    now = datetime.datetime.utcnow()
    row = {'aaa': True, 'bbb': 4, 'ccc': ['ccc'], 'ddd': now}

    self.assertEqual(
        TEST_TABLE._CreateInsertionID(**row),
        TEST_TABLE._CreateInsertionID(**row))

  def testCreateInsertionID_OmittedNullable(self):

    row_1 = {'aaa': True, 'bbb': 4, 'ccc': ['ccc'], 'ddd': None}
    row_2 = {'aaa': True, 'bbb': 4, 'ccc': ['ccc']}

    self.assertEqual(
        TEST_TABLE._CreateInsertionID(**row_1),
        TEST_TABLE._CreateInsertionID(**row_2))

  def testCreateInsertionID_Mismatch(self):

    row_1 = {'aaa': True, 'bbb': 4}
    row_2 = {'aaa': True, 'bbb': 5}

    self.assertNotEqual(
        TEST_TABLE._CreateInsertionID(**row_1),
        TEST_TABLE._CreateInsertionID(**row_2))

  def testDoInsertRow_Failure(self):

    self.mock_client.dataset.side_effect = Exception

    self.assertEntityCount(bigquery.FailedInsertion, 0)

    now = datetime.datetime.utcnow()
    row_values = {'aaa': True, 'bbb': 4, 'ccc': ['ccc'], 'ddd': now}
    TEST_TABLE._DoInsertRow(**row_values)

    self.assertTrue(tables.monitoring.row_insertions.Failure.called)
    self.assertEntityCount(bigquery.FailedInsertion, 1)

    failed_insert_id = TEST_TABLE._CreateInsertionID(**row_values)
    failed_insert_key = ndb.Key(bigquery.FailedInsertion, failed_insert_id)
    failed_insert = failed_insert_key.get()
    self.assertIsNotNone(failed_insert)

  def testDoInsertRow_Success(self):

    mock_dataset = mock.Mock()
    mock_table = mock.Mock()
    self.mock_client.dataset.return_value = mock_dataset
    mock_dataset.table.return_value = mock_table

    now = datetime.datetime.utcnow()
    row_values = {'aaa': True, 'bbb': 4, 'ccc': ['ccc'], 'ddd': now}
    TEST_TABLE._DoInsertRow(**row_values)

    self.assertTrue(mock_table.insert_data.called)
    self.assertTrue(tables.monitoring.row_insertions.Success.called)
    self.assertEntityCount(bigquery.FailedInsertion, 0)


if __name__ == '__main__':
  basetest.main()
