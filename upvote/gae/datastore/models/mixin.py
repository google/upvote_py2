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

"""Mixins for Upvote Datastore Models."""

from upvote.shared import constants


class Base(object):
  """Mixin for base NDB Models."""

  def GetPlatformName(self):
    return None

  def GetClientName(self):
    return None

  def to_dict(self, include=None, exclude=None):  # pylint: disable=g-bad-name
    """Convert the model to a dict."""
    result = super(Base, self).to_dict(include=include, exclude=exclude)

    if exclude is None or 'id' not in exclude:
      # Check for the key just in case put() hasn't been called yet.
      if hasattr(self, 'key') and self.key is not None:
        result['id'] = self.key.id()
        result['key'] = self.key.urlsafe()

    if exclude is None or 'operating_system_family' not in exclude:
      platform_name = self.GetPlatformName()
      if platform_name:
        result['operating_system_family'] = platform_name

    return result


class Bit9(Base):
  """Mixin for Bit9 NDB Models."""

  def GetPlatformName(self):
    return constants.PLATFORM.WINDOWS

  def GetClientName(self):
    return constants.CLIENT.BIT9


class Santa(Base):
  """Mixin for Santa NDB Models."""

  def GetPlatformName(self):
    return constants.PLATFORM.MACOS

  def GetClientName(self):
    return constants.CLIENT.SANTA

