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

"""Tests for json_utils."""

import datetime
import json

from google.appengine.ext import ndb

from common.testing import basetest
from upvote.gae.datastore.models import event as event_models
from upvote.gae.datastore.models import santa
from upvote.gae.utils import json_utils
from upvote.shared import constants


class TestModel(ndb.Model):
  datetime_prop = ndb.DateTimeProperty()
  int_prop = ndb.IntegerProperty()
  string_prop = ndb.StringProperty()


class BaseEncoderTest(basetest.AppEngineTestCase):

  def setUp(self):

    super(BaseEncoderTest, self).setUp()

    self.test_model = TestModel(
        datetime_prop=datetime.datetime(2015, 6, 3, 12, 30, 0),
        int_prop=111,
        string_prop='STRING!')
    self.test_key = self.test_model.put()

    self.blockable_key = ndb.Key(
        santa.SantaBlockable, 'aaaabbbbccccddddeeeeffffgggg')
    self.santa_event = event_models.SantaEvent(
        id='2324342',
        blockable_key=self.blockable_key,
        event_type=constants.EVENT_TYPE.ALLOW_UNKNOWN,
        executing_user='user1',
        file_name='Product.app',
        file_path='/Applications/Product.app/Contents/MacOs',
        host_id='AAAAAAAA-1111-BBBB-2222-CCCCCCCCCCCC',
        last_blocked_dt=datetime.datetime(2015, 4, 1, 17, 0, 0),
        first_blocked_dt=datetime.datetime(2015, 4, 1, 17, 0, 0))

  def _PerformEncoding(self, to_encode):
    encoded = self.json_encoder.encode(to_encode)
    return json.loads(encoded)

  def _VerifyEncoding(self, expected, actual):

    if isinstance(expected, list):
      self.assertTrue(isinstance(actual, list))
      self.assertEqual(len(expected), len(actual))
      for i, j in zip(sorted(expected), sorted(actual)):
        self._VerifyEncoding(i, j)

    elif isinstance(expected, dict):
      self.assertTrue(isinstance(actual, dict))
      # assertDictEqual would be more concise, but this keeps us from having to
      # update the expected dict every time there's a model change, e.g.
      # SantaEvent.
      for key, value in expected.iteritems():
        self.assertIn(key, actual)
        self.assertEqual(value, actual[key])

    else:
      self.assertEqual(expected, actual)


class JSONEncoderTest(BaseEncoderTest):

  def setUp(self):
    super(JSONEncoderTest, self).setUp()
    self.json_encoder = json_utils.JSONEncoder()

  def testEncode_Set(self):
    actual = self._PerformEncoding(set(['aaa', 'bbb', 'ccc']))
    self._VerifyEncoding(['aaa', 'bbb', 'ccc'], actual)

  def testEncode_Frozenset(self):
    actual = self._PerformEncoding(frozenset(['aaa', 'bbb', 'ccc']))
    self._VerifyEncoding(['aaa', 'bbb', 'ccc'], actual)

  def testEncode_Datetime_Default(self):
    encoder = json_utils.JSONEncoder(
        datetime_format=json_utils.DEFAULT_DATETIME_FORMAT)
    actual = json.loads(encoder.encode(datetime.datetime(2015, 4, 1, 17, 0, 0)))
    self._VerifyEncoding('2015-04-01T17:00Z', actual)

  def testEncode_Datetime_Extended(self):
    encoder = json_utils.JSONEncoder(
        datetime_format=json_utils.EXTENDED_DATETIME_FORMAT)
    actual = json.loads(
        encoder.encode(datetime.datetime(2015, 4, 1, 17, 11, 22, 333333)))
    self._VerifyEncoding('2015-04-01T17:11:22.333333Z', actual)

  def testEncode_Date(self):
    actual = self._PerformEncoding(datetime.date(2014, 2, 3))
    self._VerifyEncoding('2014-02-03', actual)

  def testEncode_Time(self):
    actual = self._PerformEncoding(datetime.time(10, 20, 30))
    self._VerifyEncoding('10:20:30', actual)

  def testEncode_Key(self):
    expected = self.test_key.urlsafe()
    actual = self._PerformEncoding(self.test_key)
    self._VerifyEncoding(expected, actual)

  def testEncode_Model(self):
    expected = {
        'datetime_prop': '2015-06-03T12:30Z',
        'int_prop': 111,
        'string_prop': 'STRING!'}
    actual = self._PerformEncoding(self.test_model)
    self._VerifyEncoding(expected, actual)

  def testEncode_SantaEvent(self):

    # Test the encoding of a single SantaEvent.
    expected = {
        'blockable_key': self.blockable_key.urlsafe(),
        'class_': ['Event', 'SantaEvent'],
        'event_type': constants.EVENT_TYPE.ALLOW_UNKNOWN,
        'executing_user': 'user1',
        'file_name': 'Product.app',
        'file_path': '/Applications/Product.app/Contents/MacOs',
        'host_id': 'AAAAAAAA-1111-BBBB-2222-CCCCCCCCCCCC',
        'id': '2324342',
        'last_blocked_dt': '2015-04-01T17:00Z',
        'first_blocked_dt': '2015-04-01T17:00Z',
    }
    actual = self._PerformEncoding(self.santa_event)
    self._VerifyEncoding(expected, actual)

    # Test the encoding of a SantaEvent list.
    actual = self._PerformEncoding([self.santa_event])
    self._VerifyEncoding([expected], actual)

  def testEncodeBoolean(self):
    """Test encoding a single Boolean value."""
    actual = self._PerformEncoding(True)
    self._VerifyEncoding(True, actual)


class JSONEncoderJavascriptTest(BaseEncoderTest):

  def setUp(self):
    super(JSONEncoderJavascriptTest, self).setUp()
    self.json_encoder = json_utils.JSONEncoderJavaScript()

  def testEncode_Set(self):
    actual = self._PerformEncoding(set(['aaa', 'bbb', 'ccc']))
    self._VerifyEncoding(['aaa', 'bbb', 'ccc'], actual)

  def testEncode_Frozenset(self):
    actual = self._PerformEncoding(frozenset(['aaa', 'bbb', 'ccc']))
    self._VerifyEncoding(['aaa', 'bbb', 'ccc'], actual)

  def testEncode_Datetime(self):
    actual = self._PerformEncoding(datetime.datetime(2015, 4, 1, 17, 0, 0))
    self._VerifyEncoding('2015-04-01T17:00Z', actual)

  def testEncode_Date(self):
    actual = self._PerformEncoding(datetime.date(2014, 2, 3))
    self._VerifyEncoding('2014-02-03', actual)

  def testEncode_Time(self):
    actual = self._PerformEncoding(datetime.time(10, 20, 30))
    self._VerifyEncoding('10:20:30', actual)

  def testEncode_Key(self):
    expected = self.test_key.urlsafe()
    actual = self._PerformEncoding(self.test_key)
    self._VerifyEncoding(expected, actual)

  def testEncode_Model(self):
    expected = {
        'datetimeProp': '2015-06-03T12:30Z',
        'intProp': 111,
        'stringProp': 'STRING!'}
    actual = self._PerformEncoding(self.test_model)
    self._VerifyEncoding(expected, actual)

  def testEncode_SantaEvent(self):

    # Test the encoding of a single SantaEvent.
    expected = {
        'blockableKey': self.blockable_key.urlsafe(),
        'class_': ['Event', 'SantaEvent'],
        'eventType': constants.EVENT_TYPE.ALLOW_UNKNOWN,
        'executingUser': 'user1',
        'fileName': 'Product.app',
        'filePath': '/Applications/Product.app/Contents/MacOs',
        'hostId': 'AAAAAAAA-1111-BBBB-2222-CCCCCCCCCCCC',
        'id': '2324342',
        'lastBlockedDt': '2015-04-01T17:00Z',
        'firstBlockedDt': '2015-04-01T17:00Z',
    }
    actual = self._PerformEncoding(self.santa_event)
    self._VerifyEncoding(expected, actual)

    # Test the encoding of a SantaEvent list.
    actual = self._PerformEncoding([self.santa_event])
    self._VerifyEncoding([expected], actual)

  def testEncodeBoolean(self):
    """Test encoding a single Boolean value."""
    actual = self._PerformEncoding(True)
    self._VerifyEncoding(True, actual)


class JSONDecoderTest(basetest.AppEngineTestCase):

  def testDecode_Datetime_Default(self):
    decoder = json_utils.JSONDecoder(
        datetime_format=json_utils.DEFAULT_DATETIME_FORMAT)
    encoded_str = '{"aaa": "2018-07-09T10:11Z"}'
    expected = {'aaa': datetime.datetime(2018, 7, 9, 10, 11, 0, 0)}
    actual = decoder.decode(encoded_str)
    self.assertEqual(expected, actual)

  def testDecode_Datetime_Extended(self):
    decoder = json_utils.JSONDecoder(
        datetime_format=json_utils.EXTENDED_DATETIME_FORMAT)
    encoded_str = '{"aaa": "2018-07-09T11:22:33.444444Z"}'
    expected = {'aaa': datetime.datetime(2018, 7, 9, 11, 22, 33, 444444)}
    actual = decoder.decode(encoded_str)
    self.assertEqual(expected, actual)


if __name__ == '__main__':
  basetest.main()
