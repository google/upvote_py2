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

"""Handler for bit9_api cron jobs."""

import datetime
import logging
import random

from google.appengine.ext import deferred
from google.appengine.ext import ndb

from upvote.gae.datastore.models import base
from upvote.gae.datastore.models import bit9
from upvote.gae.modules.bit9_api import change_set
from upvote.gae.modules.bit9_api import constants as bit9_constants
from upvote.gae.modules.bit9_api import monitoring
from upvote.gae.modules.bit9_api import sync
from upvote.gae.modules.bit9_api import utils
from upvote.gae.modules.bit9_api.api import api
from upvote.gae.shared.common import handlers
from upvote.gae.shared.common import query_utils
from upvote.gae.shared.common import taskqueue_utils
from upvote.gae.shared.common import user_map
from upvote.shared import constants


_PULL_MAX_QUEUE_SIZE = 10
_DISPATCH_MAX_QUEUE_SIZE = 10


class CommitAllChangeSets(handlers.UpvoteRequestHandler):
  """Attempt a deferred commit for each Blockable with pending change sets."""

  def get(self):
    changes = bit9.RuleChangeSet.query(
        projection=[bit9.RuleChangeSet.blockable_key], distinct=True).fetch()

    change_count = len(changes)
    logging.info('Retrieved %d pending Bit9 change(s)', change_count)
    monitoring.pending_changes.Set(change_count)

    # Don't over-defer to the bit9-commit-change queue, otherwise it can back up
    # real fast with duplicate tasks in the event of a large backlog.
    queue_size = taskqueue_utils.QueueSize(
        queue=constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, deadline=30)
    available = max(20 - queue_size, 0)
    logging.info('Deferring %d Bit9 change(s)', available)

    # Randomly sample from the outstanding changes in order to avoid
    # head-of-the-line blocking due to unsynced hosts, for example.
    sample_size = min(change_count, available)
    selected_changes = random.sample(changes, sample_size)

    blockable_keys = [change.blockable_key for change in selected_changes]
    for blockable_key in blockable_keys:
      change_set.DeferCommitBlockableChangeSet(blockable_key)


class UpdateBit9Policies(handlers.UpvoteRequestHandler):
  """Ensures locally cached policies are up-to-date."""

  def get(self):
    policies_future = bit9.Bit9Policy.query().fetch_async()

    active_policies = (api.Policy.query()
                       .filter(api.Policy.total_computers > 0)
                       .execute(utils.CONTEXT))
    local_policies = {
        policy.key.id(): policy for policy in policies_future.get_result()}
    policies_to_update = []
    for policy in active_policies:
      try:
        level = constants.BIT9_ENFORCEMENT_LEVEL.MAP_FROM_INTEGRAL_LEVEL[
            policy.enforcement_level]
      except KeyError:
        logging.warning(
            'Unknown enforcement level "%s". Skipping...',
            policy.enforcement_level)
        continue
      local_policy = local_policies.get(str(policy.id))

      if local_policy is None:
        new_policy = bit9.Bit9Policy(
            id=str(policy.id), name=policy.name, enforcement_level=level)
        policies_to_update.append(new_policy)
      else:
        dirty = False
        if local_policy.name != policy.name:
          local_policy.name = policy.name
          dirty = True
        if local_policy.enforcement_level != level:
          local_policy.enforcement_level = level
          dirty = True
        if dirty:
          policies_to_update.append(local_policy)

    if policies_to_update:
      logging.info('Updating %s policies', len(policies_to_update))
      ndb.put_multi(policies_to_update)


class CountEventsToPull(handlers.UpvoteRequestHandler):

  def get(self):
    queue_length = (
        api.Event.query()
        .filter(api.Event.id > sync.GetLastSyncedId())
        .filter(api.Event.file_catalog_id > 0)
        .filter(sync.BuildEventSubtypeFilter())
        .count(utils.CONTEXT))
    logging.info(
        'There are currently %d events waiting in Bit9', queue_length)
    monitoring.events_to_pull.Set(queue_length)


class PullEvents(handlers.UpvoteRequestHandler):

  def get(self):
    taskqueue_utils.CappedDefer(
        sync.Pull, _PULL_MAX_QUEUE_SIZE, queue=constants.TASK_QUEUE.BIT9_PULL)


class CountEventsToProcess(handlers.UpvoteRequestHandler):

  def get(self):
    events_to_process = sync._UnsyncedEvent.query().count()  # pylint: disable=protected-access
    logging.info('There are currently %d unprocessed events', events_to_process)
    monitoring.events_to_process.Set(events_to_process)


class ProcessEvents(handlers.UpvoteRequestHandler):

  def get(self):
    taskqueue_utils.CappedDefer(
        sync.Dispatch, _DISPATCH_MAX_QUEUE_SIZE,
        queue=constants.TASK_QUEUE.BIT9_DISPATCH)
