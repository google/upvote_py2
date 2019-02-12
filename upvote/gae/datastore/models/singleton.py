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

import os

from google.appengine.ext import ndb

from google.appengine.ext.ndb import polymodel
from common.cloud_kms import kms_ndb


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


class Bit9ApiAuth(Singleton):
  """The Bit9 API key.

  This class is intended to be a singleton as there should only be a single
  Bit9 API key associated with a project.
  """
  api_key = kms_ndb.EncryptedBlobProperty('bit9', 'ring', 'global')


class VirusTotalApiAuth(Singleton):
  """The VirusTotal API key.

  This class is intended to be a singleton as there should only be a single
  VirusTotal API key associated with a project.
  """
  api_key = kms_ndb.EncryptedBlobProperty('virustotal', 'ring', 'global')


class SiteXsrfSecret(Singleton):
  """A model for storing the site's xsrf key."""
  secret = ndb.StringProperty()

  @classmethod
  def GetSecret(cls):
    inst = super(SiteXsrfSecret, cls).GetInstance()
    if inst is None:
      # The secret length should match the block size of the hash function.
      inst = cls.SetInstance(secret=os.urandom(64).encode('hex'))
    return inst.secret.decode('hex')
