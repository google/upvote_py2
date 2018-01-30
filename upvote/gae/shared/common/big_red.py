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

"""Big red button, aka BRB."""

import logging

from upvote.gae.shared.models import cache


class BigRedButton(object):
  """Object Util for dealing with emergency lockdown or release."""
  BIG_RED_BUTTON = 'big_red_button'
  BIG_RED_BUTTON_STOP1 = 'big_red_button_stop1'
  BIG_RED_BUTTON_STOP2 = 'big_red_button_stop2'
  BIG_RED_BUTTON_GO1 = 'big_red_button_go1'
  BIG_RED_BUTTON_GO2 = 'big_red_button_go2'
  ALL_SWITCHES = [BIG_RED_BUTTON,
                  BIG_RED_BUTTON_STOP1,
                  BIG_RED_BUTTON_STOP2,
                  BIG_RED_BUTTON_GO1,
                  BIG_RED_BUTTON_GO2]

  def get_switch_value(self, switch):
    return cache.KeyValueCache.get_or_insert(switch, value=False).value

  def set_switch_value(self, switch, value):
    switch_cache = cache.KeyValueCache.get_or_insert(switch)
    switch_cache.value = value
    switch_cache.put()

  @property
  def stop_stop_stop(self):
    return (self.get_switch_value(self.BIG_RED_BUTTON) and
            self.get_switch_value(self.BIG_RED_BUTTON_STOP1) and
            self.get_switch_value(self.BIG_RED_BUTTON_STOP2))

  @property
  def go_go_go(self):
    return (self.get_switch_value(self.BIG_RED_BUTTON) and
            self.get_switch_value(self.BIG_RED_BUTTON_GO1) and
            self.get_switch_value(self.BIG_RED_BUTTON_GO2))

  def get_button_status(self):
    """Build and return dict of current state of BRB settings."""
    response_dict = {}
    for switch in self.ALL_SWITCHES:
      response_dict[switch] = self.get_switch_value(switch)
    response_dict['stop_stop_stop'] = self.stop_stop_stop
    response_dict['go_go_go'] = self.go_go_go
    return response_dict

  def turn_everything_off(self):
    """Sets switch values to false and puts."""
    logging.info('All Emergency switches turned off.')
    for switch in self.ALL_SWITCHES:
      self.set_switch_value(switch, False)

  def turn_on_big_red_button(self):
    logging.info('Big Red Button switched on.')
    self.set_switch_value(self.BIG_RED_BUTTON, True)

  def turn_on_stop1(self):
    logging.info('Emergency Stop 1 switched thrown.')
    if self.get_switch_value(self.BIG_RED_BUTTON):
      logging.info('Big Red Button is on, switching Stop 1 on.')
      self.set_switch_value(self.BIG_RED_BUTTON_STOP1, True)
    else:
      logging.info('Big Red Button is off, turning off all switches.')
      self.turn_everything_off()

  def turn_on_stop2(self):
    logging.info('Emergency Stop 2 switched thrown.')
    if (self.get_switch_value(self.BIG_RED_BUTTON) and
        self.get_switch_value(self.BIG_RED_BUTTON_STOP1)):
      logging.info('Big Red Button and Stop 1 are on, switching Stop 2 on.')
      self.set_switch_value(self.BIG_RED_BUTTON_STOP2, True)
    else:
      logging.info(
          'Big Red Button or Stop 1 is off, turning off all switches.')
      self.turn_everything_off()

  def turn_on_go1(self):
    logging.info('Emergency Go 1 switched thrown.')
    if self.get_switch_value(self.BIG_RED_BUTTON):
      logging.info('Big Red Button is on, switching Go 1 on.')
      self.set_switch_value(self.BIG_RED_BUTTON_GO1, True)
    else:
      logging.info('Big Red Button is off, turning off all switches.')
      self.turn_everything_off()

  def turn_on_go2(self):
    logging.info('Emergency Go 2 switched thrown.')
    if (self.get_switch_value(self.BIG_RED_BUTTON) and
        self.get_switch_value(self.BIG_RED_BUTTON_GO1)):
      logging.info('Big Red Button and Go 1 are on, switching go 2 on.')
      self.set_switch_value(self.BIG_RED_BUTTON_GO2, True)
    else:
      logging.info(
          'Big Red Button or Go 1 is off, turning off all switches.')
      self.turn_everything_off()
