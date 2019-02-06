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

"""Unit tests for event.py."""

import datetime

from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import event as event_models
from upvote.gae.datastore.models import utils as model_utils
from upvote.gae.lib.testing import basetest
from upvote.shared import constants


class EventTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(EventTest, self).setUp()

    self.earlier = datetime.datetime.utcnow()
    self.middle = self.earlier + datetime.timedelta(seconds=1)
    self.later = self.earlier + datetime.timedelta(seconds=2)

    self.blockable = test_utils.CreateBlockable()
    self.user = test_utils.CreateUser()
    self.other_user = test_utils.CreateUser()
    self.event_1 = test_utils.CreateEvent(
        self.blockable, first_blocked_dt=self.earlier,
        last_blocked_dt=self.earlier, executing_user=self.user.nickname)
    self.event_2 = test_utils.CreateEvent(
        self.blockable, first_blocked_dt=self.later, last_blocked_dt=self.later,
        executing_user=self.other_user.nickname)

    self.PatchSetting('EVENT_CREATION', constants.EVENT_CREATION.EXECUTING_USER)

  def testRunByLocalAdmin(self):
    self.assertFalse(self.event_1.run_by_local_admin)

  def testUserKey(self):
    keys = model_utils.GetEventKeysToInsert(self.event_1, [], [])
    self.event_1.key = keys[0]
    self.event_1.put()

    self.assertEqual(self.user.key, self.event_1.user_key)

  def testUserKey_BadKey(self):
    self.event_1.key = None
    self.assertIsNone(self.event_1.user_key)

  def testDedupe_Later(self):
    self.event_1.Dedupe(self.event_2)

    self.assertEqual(self.earlier, self.event_1.first_blocked_dt)
    self.assertEqual(self.later, self.event_1.last_blocked_dt)
    self.assertEqual(self.event_2.executing_user, self.event_1.executing_user)
    self.assertEqual(2, self.event_1.count)

  def testDedupe_Earlier(self):
    self.event_2.Dedupe(self.event_1)

    self.assertEqual(self.earlier, self.event_2.first_blocked_dt)
    self.assertEqual(self.later, self.event_2.last_blocked_dt)
    self.assertNotEqual(
        self.event_2.executing_user, self.event_1.executing_user)
    self.assertEqual(2, self.event_2.count)

  def testDedupe_Both(self):
    self.event_1.first_blocked_dt = self.middle
    self.event_1.last_blocked_dt = self.middle
    self.event_1.put()

    self.event_2.first_blocked_dt = self.earlier
    self.event_2.last_blocked_dt = self.later
    self.event_2.put()

    self.event_1.Dedupe(self.event_2)

    self.assertEqual(self.earlier, self.event_1.first_blocked_dt)
    self.assertEqual(self.later, self.event_1.last_blocked_dt)
    self.assertEqual(self.event_2.executing_user, self.event_1.executing_user)
    self.assertEqual(2, self.event_1.count)

  def testDedupe_NoCount(self):
    datastore_utils.DeleteProperty(self.event_2, 'count')

    self.event_1.Dedupe(self.event_2)

    self.assertEqual(2, self.event_1.count)

  def testDedupeMultiple(self):
    keys = model_utils.GetEventKeysToInsert(self.event_1, ['foo'], [])
    event1 = datastore_utils.CopyEntity(
        self.event_1,
        new_key=keys[0],
        first_blocked_dt=self.middle,
        last_blocked_dt=self.middle)
    event2 = datastore_utils.CopyEntity(
        self.event_1,
        new_key=keys[0],
        first_blocked_dt=self.earlier,
        last_blocked_dt=self.later)
    event3 = datastore_utils.CopyEntity(
        self.event_1,
        new_key=keys[0],
        first_blocked_dt=self.middle,
        last_blocked_dt=self.later)

    events = event_models.Event.DedupeMultiple([event1, event2, event3])

    self.assertLen(events, 1)

    self.assertEqual(self.earlier, events[0].first_blocked_dt)
    self.assertEqual(self.later, events[0].last_blocked_dt)
    self.assertEqual(3, events[0].count)


class Bit9EventTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(Bit9EventTest, self).setUp()

    self.user = test_utils.CreateUser()

    self.bit9_host = test_utils.CreateBit9Host()

    self.bit9_binary = test_utils.CreateBit9Binary()
    now = test_utils.Now()
    self.bit9_event = test_utils.CreateBit9Event(
        self.bit9_binary,
        host_id=self.bit9_host.key.id(),
        executing_user=self.user.nickname,
        first_blocked_dt=now,
        last_blocked_dt=now,
        id='1',
        parent=datastore_utils.ConcatenateKeys(
            self.user.key, self.bit9_host.key,
            self.bit9_binary.key))

  def testDedupe(self):
    earlier_dt = self.bit9_event.last_blocked_dt - datetime.timedelta(hours=1)
    earlier_bit9_event = datastore_utils.CopyEntity(
        self.bit9_event,
        first_blocked_dt=earlier_dt,
        last_blocked_dt=earlier_dt,
        bit9_id=self.bit9_event.bit9_id - 1,
    )

    # Always choose the larger ID.

    more_recent_deduped = datastore_utils.CopyEntity(earlier_bit9_event)
    more_recent_deduped.Dedupe(self.bit9_event)
    self.assertEquals(self.bit9_event.bit9_id, more_recent_deduped.bit9_id)

    earlier_deduped = datastore_utils.CopyEntity(self.bit9_event)
    earlier_deduped.Dedupe(earlier_bit9_event)
    self.assertEquals(self.bit9_event.bit9_id, earlier_deduped.bit9_id)

  def testDedupe_OutOfOrder(self):
    earlier_dt = self.bit9_event.last_blocked_dt - datetime.timedelta(hours=1)
    earlier_bit9_event = datastore_utils.CopyEntity(
        self.bit9_event,
        first_blocked_dt=earlier_dt,
        last_blocked_dt=earlier_dt,
        bit9_id=self.bit9_event.bit9_id + 1,  # Earlier event has larger ID
    )

    # Always choose the larger ID.

    more_recent_deduped = datastore_utils.CopyEntity(earlier_bit9_event)
    more_recent_deduped.Dedupe(self.bit9_event)
    self.assertEquals(self.bit9_event.bit9_id + 1, more_recent_deduped.bit9_id)

    earlier_deduped = datastore_utils.CopyEntity(self.bit9_event)
    earlier_deduped.Dedupe(earlier_bit9_event)
    self.assertEquals(self.bit9_event.bit9_id + 1, earlier_deduped.bit9_id)


class SantaEventTest(basetest.UpvoteTestCase):

  def testRunByLocalAdmin_False(self):
    blockable = test_utils.CreateSantaBlockable()
    event = test_utils.CreateSantaEvent(blockable, executing_user='some_user')
    self.assertFalse(event.run_by_local_admin)

  def testRunByLocalAdmin_True(self):
    blockable = test_utils.CreateSantaBlockable()
    event = test_utils.CreateSantaEvent(
        blockable, executing_user=constants.LOCAL_ADMIN.MACOS)
    self.assertTrue(event.run_by_local_admin)

  def testDedupe(self):

    blockable = test_utils.CreateSantaBlockable()
    now = datetime.datetime.utcnow()
    quarantine = event_models.QuarantineMetadata(
        data_url='http://notbad.com',
        referer_url='http://sourceforge.com',
        downloaded_dt=datetime.datetime.utcnow(),
        agent_bundle_id='123456')
    event = test_utils.CreateSantaEvent(
        blockable, last_blocked_dt=now, quarantine=quarantine)
    later_dt = event.last_blocked_dt + datetime.timedelta(seconds=1)
    later_event = datastore_utils.CopyEntity(
        event,
        quarantine=None,
        event_type=constants.EVENT_TYPE.BLOCK_CERTIFICATE,
        last_blocked_dt=later_dt)

    event.Dedupe(later_event)

    self.assertEqual(constants.EVENT_TYPE.BLOCK_CERTIFICATE, event.event_type)
    self.assertIsNotNone(event.quarantine)

  def testDedupe_AddOldQuarantineData(self):

    blockable = test_utils.CreateSantaBlockable()
    now = datetime.datetime.utcnow()
    event = test_utils.CreateSantaEvent(
        blockable, quarantine=None, first_blocked_dt=now)
    quarantine = event_models.QuarantineMetadata(
        data_url='http://notbad.com',
        referer_url='http://sourceforge.com',
        downloaded_dt=datetime.datetime.utcnow(),
        agent_bundle_id='123456')
    earlier_dt = event.first_blocked_dt - datetime.timedelta(seconds=1)
    earlier_event = datastore_utils.CopyEntity(
        event,
        quarantine=quarantine,
        event_type=constants.EVENT_TYPE.BLOCK_CERTIFICATE,
        first_blocked_dt=earlier_dt)

    event.Dedupe(earlier_event)

    self.assertNotEqual(
        constants.EVENT_TYPE.BLOCK_CERTIFICATE, event.event_type)
    self.assertIsNotNone(event.quarantine)

  def testDedupe_AddNewerQuarantineData(self):

    blockable = test_utils.CreateSantaBlockable()
    quarantine = event_models.QuarantineMetadata(
        data_url='http://notbad.com',
        referer_url='http://sourceforge.com',
        downloaded_dt=datetime.datetime.utcnow(),
        agent_bundle_id='123456')
    now = datetime.datetime.utcnow()
    event = test_utils.CreateSantaEvent(
        blockable, quarantine=quarantine, last_blocked_dt=now)
    new_quarantine = datastore_utils.CopyEntity(
        event.quarantine, data_url='http://3vil.com')
    later_dt = event.last_blocked_dt + datetime.timedelta(seconds=1)
    later_event = datastore_utils.CopyEntity(
        event, quarantine=new_quarantine, last_blocked_dt=later_dt)

    event.Dedupe(later_event)

    self.assertEqual('http://3vil.com', event.quarantine.data_url)

  def testGiantQuarantineUrl(self):
    # Ensure URLs that exceed the NDB size limit for indexed properties (1500
    # bytes) may be set on QuarantineMetadata URL fields.
    huge_url = 'http://3vil.com/' + 'a' * 1500
    blockable = test_utils.CreateSantaBlockable()
    quarantine = event_models.QuarantineMetadata(data_url=huge_url)
    event = test_utils.CreateSantaEvent(blockable, quarantine=quarantine)
    event.put()


if __name__ == '__main__':
  basetest.main()
