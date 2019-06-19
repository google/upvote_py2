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

"""Use this module to store things that need to be encrypted.

Provides EncryptedBlobProperty which is used for transperent encryption
of properties in ndb. A common usecase is safely saving API keys, but if
you are not certain that this technique applies to your use case please
consult the security team.

Example Usage:
# KEY_NAME, KEYRING, and KEY_LOCATION are explained in README
class SimpleApiKey(ndb.Model):
  api_key = kms.EncryptedBlobProperty(KEY_NAME, KEYRING, KEY_LOCATION)

Using with googleapiclient[https://developers.google.com/api-client-library]:

api_key = SimpleApiKey.get_by_id(HOWEVER_YOU_WANT_YOUR_API_ID)
client = googleapiclient.discovery.build(API, VERSION, developerKey=api_key)
"""
from google.appengine.ext import ndb

from common.cloud_kms import cloud_kms


class EncryptedBlobProperty(ndb.BlobProperty):
  """BlobProperty class that encrypts/decrypts data seamlessly on get/set."""

  _key_name = None
  _key_ring = None
  _key_location = None

  def __init__(self, key_name, key_ring, key_location, *args, **kwargs):
    super(EncryptedBlobProperty, self).__init__(*args, **kwargs)
    self._key_name = key_name
    self._key_ring = key_ring
    self._key_location = key_location

  def _Decrypt(self, value):
    return cloud_kms.Decrypt(value, self._key_name, self._key_ring,
                             key_location=self._key_location)

  def _Encrypt(self, value):
    return cloud_kms.Encrypt(value, self._key_name, self._key_ring,
                             key_location=self._key_location)

  def _set_value(self, entity, value):
    encrypted_value = self._Encrypt(value).encode('utf8')
    super(EncryptedBlobProperty, self)._set_value(entity, encrypted_value)

  def _get_value(self, entity):
    encrypted_value = super(EncryptedBlobProperty, self)._get_value(entity)
    return self._Decrypt(encrypted_value)
