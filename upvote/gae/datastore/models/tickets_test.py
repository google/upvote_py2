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

"""Tests for ticket models."""

from upvote.gae.datastore.models import tickets
from upvote.gae.lib.testing import basetest


class TicketTest(basetest.UpvoteTestCase):

  def testHostException_GetOpenOrInsertDidInsert(self):
    ticket1, inserted = (
        tickets.HostExceptionTicket.get_open_or_insert_did_insert(
            'foo', 'bar'))
    self.assertTrue(inserted)

    ticket2, inserted = (
        tickets.HostExceptionTicket.get_open_or_insert_did_insert(
            'foo', 'bar'))
    self.assertFalse(inserted)
    self.assertEqual(ticket1, ticket2)

  def testHostException_GetOpenOrInsertDidInsert_Closed(self):
    ticket1, inserted = (
        tickets.HostExceptionTicket.get_open_or_insert_did_insert(
            'foo', 'bar'))
    self.assertTrue(inserted)

    ticket1.is_open = False
    ticket1.put()

    ticket2, inserted = (
        tickets.HostExceptionTicket.get_open_or_insert_did_insert(
            'foo', 'bar'))
    self.assertTrue(inserted)
    self.assertNotEqual(ticket1, ticket2)

  def testHostException_GetOpenOrInsertDidInsert_kwargs(self):
    ticket, _ = tickets.HostExceptionTicket.get_open_or_insert_did_insert(
        'foo', 'bar', ticket_id='baz')
    self.assertTrue('baz', ticket.ticket_id)


if __name__ == '__main__':
  basetest.main()
