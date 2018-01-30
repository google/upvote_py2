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

"""Module for performing common group operations."""


class AbstractGroupManager(object):
  """The interface required for user grouping in Upvote."""

  def DoesGroupExist(self, groupname):
    """Determines if a given group exists.

    Args:
      groupname: The group name to check.

    Returns:
      Whether the group exists.
    """
    raise NotImplementedError()

  def AllMembers(self, groupname):
    """Returns all the members of the provided group.

    Args:
      groupname: str, The group for which the members should be retrieved.

    Returns:
      A list<str> of all user emails in the given group.
    """
    raise NotImplementedError()


class GroupManager(AbstractGroupManager):
  """An static implementation of the groups interface."""
  _GROUPS = {
      'admin-users': []
  }

  def DoesGroupExist(self, groupname):
    """See base class for description."""
    return groupname in self._GROUPS

  def AllMembers(self, groupname):
    """See base class for description."""
    return self._GROUPS[groupname]
