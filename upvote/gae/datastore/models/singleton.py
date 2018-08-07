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

"""Datastore Singleton module."""

from google.appengine.ext.ndb import polymodel


class Singleton(polymodel.PolyModel):
  """A base class to support singleton models."""

  @classmethod
  def _GetId(cls):
    """The ID to be used for the singleton model instance.

    WARNING: This must be unique to all singleton classes in the app.

    Returns:
      The string to be used as the sole ID for the model type.
    """
    return cls._class_name()

  @classmethod
  def GetInstance(cls):
    return cls.get_by_id(cls._GetId())

  @classmethod
  def SetInstance(cls, **properties):
    inst = cls(id=cls._GetId(), **properties)
    inst.put()
    return inst
