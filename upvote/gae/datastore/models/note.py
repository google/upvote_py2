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

"""Model definitions for Upvote notes."""

import hashlib

from google.appengine.ext import ndb
from google.appengine.ext.ndb import polymodel


class Note(polymodel.PolyModel):
  """An entity used for annotating other entities.

  Attributes:
    message: The text of the note.
    author: The username of this note's author.
    changelists: Integer list of relevant changelist IDs.
    bugs: Integer list of relevant bug IDs.
    tickets: Integer list of relevant ticket IDs.
  """
  message = ndb.TextProperty()
  author = ndb.StringProperty()
  changelists = ndb.IntegerProperty(repeated=True)
  bugs = ndb.IntegerProperty(repeated=True)
  tickets = ndb.IntegerProperty(repeated=True)
  recorded_dt = ndb.DateTimeProperty(auto_now_add=True)

  @classmethod
  def GenerateKey(cls, message, parent):
    key_hash = hashlib.sha256(message).hexdigest()
    return ndb.Key(Note, key_hash, parent=parent)

