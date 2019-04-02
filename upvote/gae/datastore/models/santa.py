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

"""Models specific to Santa."""

from google.appengine.ext import ndb

from upvote.gae.datastore.models import base
from upvote.gae.datastore.models import mixin


class SantaBlockable(mixin.Santa, base.Binary):
  """An binary that has been blocked by Santa.

  key = hash of blockable

  Attributes:
    bundle_id: str, CFBundleIdentifier. The enclosing bundle's unique
        identifier.
    cert_sha256: str, SHA-256 of the codesigning cert, if any.
  """
  bundle_id = ndb.StringProperty()

  # DEPRECATED
  cert_sha256 = ndb.StringProperty()  # Use base.Binary.cert_key

  @property
  def cert_id(self):
    return (self.cert_key and self.cert_key.id()) or self.cert_sha256

