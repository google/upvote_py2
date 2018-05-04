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

"""Handlers for interacting with the bit9_arbiter RPC service."""

import datetime
import httplib

from upvote.gae.datastore.models import base as base_db
from upvote.gae.modules.bit9_api import change_set
from upvote.gae.modules.bit9_api import constants as bit9_constants
from upvote.gae.shared.common import handlers
from upvote.shared import constants

_HOST_HEALTH_PROPS = bit9_constants.UpvoteHostHealthProperties
_HOST_HEALTH_TIMEOUT = datetime.timedelta(minutes=5).total_seconds()
_ASSOCIATED_HOSTS_TIMEOUT = datetime.timedelta(minutes=15).total_seconds()


class CommitBlockableChangeSet(handlers.UpvoteRequestHandler):
  """Triggers a deferred commit attempt for a given Blockable's change sets."""

  def get(self, blockable_id):
    blockable = base_db.Blockable.get_by_id(blockable_id)
    if blockable is None:
      self.abort(httplib.NOT_FOUND, explanation='Blockable does not exist')

    platform = blockable.GetPlatformName()
    if platform != constants.PLATFORM.WINDOWS:
      self.abort(
          httplib.BAD_REQUEST,
          explanation='Invalid Blockable platform: %s' % (platform))

    change_set.DeferCommitBlockableChangeSet(blockable.key)
