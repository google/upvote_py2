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

"""Tests for the big red button."""

from upvote.gae.datastore.models import cache
from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import big_red


class BigRedButtonTests(basetest.UpvoteTestCase):

  def setUp(self):
    super(BigRedButtonTests, self).setUp()

    self.big_red_button = big_red.BigRedButton()

    self.SetSwitches(False, self.big_red_button.ALL_SWITCHES)

  def tearDown(self):
    self.testbed.deactivate()

  def SetSwitches(self, switch_value, switch_list):
    for switch in switch_list:
      switch_cache = cache.KeyValueCache.get_or_insert(switch)
      switch_cache.value = switch_value
      switch_cache.put()

  def testCheckStopStopStopOff(self):
    self.assertFalse(self.big_red_button.stop_stop_stop)

  def testCheckStopStopStopPartial(self):
    self.SetSwitches(True, [self.big_red_button.BIG_RED_BUTTON,
                            self.big_red_button.BIG_RED_BUTTON_STOP1])
    self.assertFalse(self.big_red_button.stop_stop_stop)

  def testCheckStopStopStopOn(self):
    self.SetSwitches(True, [self.big_red_button.BIG_RED_BUTTON,
                            self.big_red_button.BIG_RED_BUTTON_STOP1,
                            self.big_red_button.BIG_RED_BUTTON_STOP2])
    self.assertTrue(self.big_red_button.stop_stop_stop)

  def testCheckGoGoGoOff(self):
    self.assertFalse(self.big_red_button.go_go_go)

  def testCheckGoGoGoPartial(self):
    self.SetSwitches(True, [self.big_red_button.BIG_RED_BUTTON,
                            self.big_red_button.BIG_RED_BUTTON_GO1])
    self.assertFalse(self.big_red_button.go_go_go)

  def testCheckGoGoGoOn(self):
    self.SetSwitches(True, [self.big_red_button.BIG_RED_BUTTON,
                            self.big_red_button.BIG_RED_BUTTON_GO1,
                            self.big_red_button.BIG_RED_BUTTON_GO2])
    self.assertTrue(self.big_red_button.go_go_go)

  def testCheckButtonStatus(self):
    self.SetSwitches(True, [self.big_red_button.BIG_RED_BUTTON,
                            self.big_red_button.BIG_RED_BUTTON_GO1,
                            self.big_red_button.BIG_RED_BUTTON_GO2])

    expected_dict = {self.big_red_button.BIG_RED_BUTTON: True,
                     self.big_red_button.BIG_RED_BUTTON_STOP1: False,
                     self.big_red_button.BIG_RED_BUTTON_STOP2: False,
                     self.big_red_button.BIG_RED_BUTTON_GO1: True,
                     self.big_red_button.BIG_RED_BUTTON_GO2: True,
                     'stop_stop_stop': self.big_red_button.stop_stop_stop,
                     'go_go_go': self.big_red_button.go_go_go}

    self.assertEqual(expected_dict, self.big_red_button.get_button_status())

  def testTurnEverythingOff(self):
    self.SetSwitches(True, self.big_red_button.ALL_SWITCHES)
    for switch in self.big_red_button.ALL_SWITCHES:
      self.assertTrue(self.big_red_button.get_switch_value(switch))

    self.big_red_button.turn_everything_off()
    for switch in self.big_red_button.ALL_SWITCHES:
      self.assertFalse(self.big_red_button.get_switch_value(switch))

  def testTurnOnBigRedButton(self):
    self.big_red_button.turn_on_big_red_button()
    self.assertTrue(self.big_red_button.get_switch_value(
        self.big_red_button.BIG_RED_BUTTON))

  def testTurnOnStop1WithBRBOn(self):
    self.SetSwitches(True, [self.big_red_button.BIG_RED_BUTTON])
    self.big_red_button.turn_on_stop1()

    self.assertTrue(self.big_red_button.get_switch_value(
        self.big_red_button.BIG_RED_BUTTON_STOP1))

  def testTurnOnStop1WithBRBOff(self):
    self.big_red_button.turn_on_stop1()

    self.assertFalse(self.big_red_button.get_switch_value(
        self.big_red_button.BIG_RED_BUTTON_STOP1))

  def testTurnOnStop2WithBRBAndStop1On(self):
    self.SetSwitches(True, [self.big_red_button.BIG_RED_BUTTON,
                            self.big_red_button.BIG_RED_BUTTON_STOP1])
    self.big_red_button.turn_on_stop2()

    self.assertTrue(self.big_red_button.get_switch_value(
        self.big_red_button.BIG_RED_BUTTON_STOP2))

  def testTurnOnStop2WithStop1Off(self):
    self.SetSwitches(True, [self.big_red_button.BIG_RED_BUTTON])
    self.big_red_button.turn_on_stop2()

    self.assertFalse(self.big_red_button.get_switch_value(
        self.big_red_button.BIG_RED_BUTTON_STOP2))

  def testTurnOnGo1WithBRBOn(self):
    self.SetSwitches(True, [self.big_red_button.BIG_RED_BUTTON])
    self.big_red_button.turn_on_go1()

    self.assertTrue(self.big_red_button.get_switch_value(
        self.big_red_button.BIG_RED_BUTTON_GO1))

  def testTurnOnGo1WithBRBOff(self):
    self.big_red_button.turn_on_go1()

    self.assertFalse(self.big_red_button.get_switch_value(
        self.big_red_button.BIG_RED_BUTTON_GO1))

  def testTurnOnGo2WithBRBAndGo1On(self):
    self.SetSwitches(True, [self.big_red_button.BIG_RED_BUTTON,
                            self.big_red_button.BIG_RED_BUTTON_GO1])
    self.big_red_button.turn_on_go2()

    self.assertTrue(self.big_red_button.get_switch_value(
        self.big_red_button.BIG_RED_BUTTON_GO2))

  def testTurnOnGo2WithGo1Off(self):
    self.SetSwitches(True, [self.big_red_button.BIG_RED_BUTTON])
    self.big_red_button.turn_on_go2()

    self.assertFalse(self.big_red_button.get_switch_value(
        self.big_red_button.BIG_RED_BUTTON_GO2))


if __name__ == '__main__':
  basetest.main()
