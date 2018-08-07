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

import upvote.gae.shared.common.google_cloud_lib_fixer  # pylint: disable=unused-import
# pylint: disable=g-bad-import-order,g-import-not-at-top
from google.cloud import exceptions

from upvote.gae.bigquery import tables
from upvote.gae.lib.testing import basetest
from upvote.shared import constants


TEST_TABLE = tables.BigQueryTable(
    constants.BIGQUERY_TABLE.BINARY, [
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
        tables.Column(
            name='eee',
            field_type=tables.FIELD_TYPE.STRING,
            mode=tables.MODE.NULLABLE,
            choices=['e1', 'e2', 'e3']),
        tables.Column(
            name='fff',
            field_type=tables.FIELD_TYPE.STRING,
            mode=tables.MODE.REPEATED,
            choices=['f1', 'f2', 'f3']),
    ])


class RowValueToStrTest(basetest.UpvoteTestCase):

  def testList(self):
    self.assertEqual(
        "['111', '222', '333']",
        tables._RowValueToStr([111, 222, 333]))

  def testUnicode(self):
    self.assertEqual(
        'aaa???bbb', tables._RowValueToStr(u'aaa\u00A2\u00A2\u00A2bbb'))

  def testNone(self):
    self.assertEqual('None', tables._RowValueToStr(None))

  def testOther(self):
    self.assertEqual('True', tables._RowValueToStr(True))
    self.assertEqual('12345', tables._RowValueToStr(12345))
    self.assertEqual(
        '2018-07-31 10:11:12',
        tables._RowValueToStr(datetime.datetime(2018, 7, 31, 10, 11, 12)))


class SendToBigQueryTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(SendToBigQueryTest, self).setUp(patch_send_to_bigquery=False)
    self.row_dict = {'aaa': 111, 'bbb': 222, 'ccc': 333}
    self.row_id = TEST_TABLE.CreateRowId(**self.row_dict)
    self.Patch(tables, '_Sleep')

  def testMissingDataset_Created(self):

    mock_client = mock.Mock(spec=tables.bigquery.Client)
    mock_client.insert_rows.side_effect = [exceptions.NotFound('OMG'), []]
    mock_client.get_dataset.side_effect = exceptions.NotFound('OMG')
    mock_client.get_table.side_effect = exceptions.NotFound('OMG')
    self.Patch(tables.bigquery, 'Client', return_value=mock_client)

    tables._SendToBigQuery(TEST_TABLE, self.row_dict)

    insert_rows_call = mock.call(
        mock.ANY, [self.row_dict], selected_fields=TEST_TABLE.schema,
        row_ids=[self.row_id])

    mock_client.insert_rows.assert_has_calls([insert_rows_call] * 2)
    mock_client.get_dataset.assert_called_once()
    mock_client.create_dataset.assert_called_once()
    mock_client.get_table.assert_called_once()
    mock_client.create_table.assert_called_once()

  def testMissingDataset_Conflict(self):

    mock_client = mock.Mock(spec=tables.bigquery.Client)
    mock_client.insert_rows.side_effect = [exceptions.NotFound('OMG'), []]
    mock_client.get_dataset.side_effect = exceptions.NotFound('OMG')
    mock_client.create_dataset.side_effect = exceptions.Conflict('WTF')
    mock_client.get_table.side_effect = exceptions.NotFound('OMG')
    self.Patch(tables.bigquery, 'Client', return_value=mock_client)

    tables._SendToBigQuery(TEST_TABLE, self.row_dict)

    insert_rows_call = mock.call(
        mock.ANY, [self.row_dict], selected_fields=TEST_TABLE.schema,
        row_ids=[self.row_id])

    mock_client.insert_rows.assert_has_calls([insert_rows_call] * 2)
    mock_client.get_dataset.assert_called_once()
    mock_client.create_dataset.assert_called_once()
    mock_client.get_table.assert_called_once()
    mock_client.create_table.assert_called_once()

  def testMissingTable_Created(self):

    mock_client = mock.Mock(spec=tables.bigquery.Client)
    mock_client.insert_rows.side_effect = [exceptions.NotFound('OMG'), []]
    mock_client.get_table.side_effect = exceptions.NotFound('OMG')
    self.Patch(tables.bigquery, 'Client', return_value=mock_client)

    tables._SendToBigQuery(TEST_TABLE, self.row_dict)

    insert_rows_call = mock.call(
        mock.ANY, [self.row_dict], selected_fields=TEST_TABLE.schema,
        row_ids=[self.row_id])

    mock_client.insert_rows.assert_has_calls([insert_rows_call] * 2)
    mock_client.get_dataset.assert_called_once()
    mock_client.create_dataset.assert_not_called()
    mock_client.get_table.assert_called_once()
    mock_client.create_table.assert_called_once()

  def testMissingTable_Conflict(self):

    mock_client = mock.Mock(spec=tables.bigquery.Client)
    mock_client.insert_rows.side_effect = [exceptions.NotFound('OMG'), []]
    mock_client.get_table.side_effect = exceptions.NotFound('OMG')
    mock_client.create_table.side_effect = exceptions.Conflict('WTF')
    self.Patch(tables.bigquery, 'Client', return_value=mock_client)

    tables._SendToBigQuery(TEST_TABLE, self.row_dict)

    insert_rows_call = mock.call(
        mock.ANY, [self.row_dict], selected_fields=TEST_TABLE.schema,
        row_ids=[self.row_id])

    mock_client.insert_rows.assert_has_calls([insert_rows_call] * 2)
    mock_client.get_dataset.assert_called_once()
    mock_client.create_dataset.assert_not_called()
    mock_client.get_table.assert_called_once()
    mock_client.create_table.assert_called_once()

  def testMissingTable_NotReady(self):

    mock_client = mock.Mock(spec=tables.bigquery.Client)
    mock_client.insert_rows.side_effect = [
        exceptions.NotFound('OMG'), exceptions.NotFound('OMG'), []]
    mock_client.get_table.side_effect = exceptions.NotFound('OMG')
    self.Patch(tables.bigquery, 'Client', return_value=mock_client)

    tables._SendToBigQuery(TEST_TABLE, self.row_dict)

    insert_rows_call = mock.call(
        mock.ANY, [self.row_dict], selected_fields=TEST_TABLE.schema,
        row_ids=[self.row_id])

    mock_client.insert_rows.assert_has_calls([insert_rows_call] * 3)
    mock_client.get_dataset.assert_called_once()
    mock_client.create_dataset.assert_not_called()
    mock_client.get_table.assert_called_once()
    mock_client.create_table.assert_called_once()
    tables._Sleep.assert_has_calls([mock.call(1), mock.call(2)])

  def testClientReturnsErrors(self):

    mock_client = mock.Mock(spec=tables.bigquery.Client)
    mock_client.insert_rows.return_value = [{'err1': 'xxx'}, {'err2': 'yyy'}]
    self.Patch(tables.bigquery, 'Client', return_value=mock_client)

    with self.assertRaises(tables.StreamingFailure):
      tables._SendToBigQuery(TEST_TABLE, self.row_dict)

  def testSuccess(self):

    mock_client = mock.Mock(spec=tables.bigquery.Client)
    mock_client.insert_rows.return_value = []
    self.Patch(tables.bigquery, 'Client', return_value=mock_client)

    tables._SendToBigQuery(TEST_TABLE, self.row_dict)
    self.assertTrue(mock_client.insert_rows.called)


class BigQueryTableTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(BigQueryTableTest, self).setUp()
    self.Patch(tables.monitoring, 'row_insertions')

  def testSchema(self):
    self.assertListEqual(
        [column.name for column in TEST_TABLE._columns],
        [column.name for column in TEST_TABLE.schema])

  def testValidateInsertion_UnexpectedColumn(self):
    with self.assertRaises(tables.UnexpectedColumn):
      TEST_TABLE._ValidateInsertion(aaa=True, bbb=4, omg='OMG')

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

  def testValidateInsertion_InvalidValue_Single(self):
    with self.assertRaises(tables.InvalidValue):
      TEST_TABLE._ValidateInsertion(aaa=True, bbb=4, eee='xyz')

  def testValidateInsertion_InvalidValue_Repeated(self):
    with self.assertRaises(tables.InvalidValue):
      TEST_TABLE._ValidateInsertion(aaa=True, bbb=4, fff=['f1', 'f2', 'xyz'])

  def testValidateInsertion_Nullable_Omitted(self):
    TEST_TABLE._ValidateInsertion(aaa=True, bbb=4)

  def testValidateInsertion_Nullable_None(self):
    TEST_TABLE._ValidateInsertion(aaa=True, bbb=4, ddd=None)

  def testValidateInsertion_Success(self):
    now = datetime.datetime.utcnow()
    TEST_TABLE._ValidateInsertion(
        aaa=True, bbb=4, ccc=['ccc'], ddd=now, eee='e1', fff=['f2', 'f3'])

  def testCreateRowId_Identical(self):

    now = datetime.datetime.utcnow()
    row = {'aaa': True, 'bbb': 4, 'ccc': ['ccc'], 'ddd': now}

    self.assertEqual(
        TEST_TABLE.CreateRowId(**row),
        TEST_TABLE.CreateRowId(**row))

  def testCreateRowId_OmittedNullable(self):

    row_1 = {'aaa': True, 'bbb': 4, 'ccc': ['ccc'], 'ddd': None}
    row_2 = {'aaa': True, 'bbb': 4, 'ccc': ['ccc']}

    self.assertEqual(
        TEST_TABLE.CreateRowId(**row_1),
        TEST_TABLE.CreateRowId(**row_2))

  def testCreateRowId_Mismatch(self):

    row_1 = {'aaa': True, 'bbb': 4}
    row_2 = {'aaa': True, 'bbb': 5}

    self.assertNotEqual(
        TEST_TABLE.CreateRowId(**row_1),
        TEST_TABLE.CreateRowId(**row_2))

  def testCreateRowId_Unicode(self):

    row_1 = {
        'aaa': True,
        'bbb': 4,
        'ccc': [u'ccc\u00A2\u00A2\u00A2'],
        'eee': u'eee\u00A3\u00A3\u00A3'}
    row_2 = {'aaa': True, 'bbb': 4, 'ccc': ['ccc???'], 'eee': 'eee???'}

    self.assertEqual(
        TEST_TABLE.CreateRowId(**row_1),
        TEST_TABLE.CreateRowId(**row_2))

  def testDoInsertRow_Failure(self):

    self.mock_send_to_bigquery.side_effect = Exception

    now = datetime.datetime.utcnow()
    row_values = {'aaa': True, 'bbb': 4, 'ccc': ['ccc'], 'ddd': now}
    TEST_TABLE._DoInsertRow(**row_values)

    self.assertTrue(tables.monitoring.row_insertions.Failure.called)

  def testDoInsertRow_Success(self):

    now = datetime.datetime.utcnow()
    row_values = {'aaa': True, 'bbb': 4, 'ccc': ['ccc'], 'ddd': now}
    TEST_TABLE._DoInsertRow(**row_values)

    self.assertTrue(self.mock_send_to_bigquery.called)
    self.assertTrue(tables.monitoring.row_insertions.Success.called)


if __name__ == '__main__':
  basetest.main()
