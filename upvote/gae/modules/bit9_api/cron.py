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

from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import base
from upvote.gae.datastore.models import bit9
from upvote.gae.datastore.models import user as user_models
from upvote.gae.lib.bit9 import api
from upvote.gae.lib.bit9 import change_set
from upvote.gae.lib.bit9 import constants as bit9_constants
from upvote.gae.lib.bit9 import monitoring
from upvote.gae.lib.bit9 import utils as bit9_utils
from upvote.gae.modules.bit9_api import sync
from upvote.gae.shared.common import handlers
from upvote.gae.shared.common import user_map
from upvote.gae.taskqueue import utils as taskqueue_utils
from upvote.shared import constants


_PULL_MAX_QUEUE_SIZE = 10
_DISPATCH_MAX_QUEUE_SIZE = 10


class CommitAllChangeSets(handlers.UpvoteRequestHandler):
  """Attempt a deferred commit for each Blockable with pending change sets."""

  def get(self):

    start_time = datetime.datetime.utcnow()

    changes = bit9.RuleChangeSet.query(
        projection=[bit9.RuleChangeSet.blockable_key], distinct=True).fetch()

    # Count the number of distinct SHA256s that have outstanding RuleChangeSets.
    blockable_keys = [change.blockable_key for change in changes]
    blockable_key_count = len(blockable_keys)
    logging.info('Retrieved %d pending change(s)', blockable_key_count)
    monitoring.pending_changes.Set(blockable_key_count)

    # Don't just throw everything into the bit9-commit-change queue, because if
    # anything is still pending when the cron fires again, the queue could start
    # to back up. Allow 3 tasks/sec for the number of seconds remaining (minus a
    # small buffer), evenly spread out over the remaining cron period.
    now = datetime.datetime.utcnow()
    cron_seconds = int(datetime.timedelta(minutes=5).total_seconds())
    elapsed_seconds = int((now - start_time).total_seconds())
    available_seconds = cron_seconds - elapsed_seconds - 10

    # Randomly sample from the outstanding changes in order to avoid
    # head-of-the-line blocking due to unsynced hosts, for example.
    sample_size = min(len(blockable_keys), 3 * available_seconds)
    selected_keys = random.sample(blockable_keys, sample_size)
    logging.info('Deferring %d pending change(s)', len(selected_keys))

    for selected_key in selected_keys:

      # Schedule the task for a random time in the remaining cron period.
      countdown = random.randint(0, available_seconds)
      change_set.DeferCommitBlockableChangeSet(
          selected_key, countdown=countdown)


class UpdateBit9Policies(handlers.UpvoteRequestHandler):
  """Ensures locally cached policies are up-to-date."""

  def get(self):
    policies_future = bit9.Bit9Policy.query().fetch_async()

    active_policies = (
        api.Policy.query().filter(api.Policy.total_computers > 0)
        .execute(bit9_utils.CONTEXT))
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
        api.Event.query().filter(api.Event.id > sync.GetLastSyncedId())
        .filter(api.Event.file_catalog_id > 0).filter(
            sync.BuildEventSubtypeFilter()).count(bit9_utils.CONTEXT))
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
