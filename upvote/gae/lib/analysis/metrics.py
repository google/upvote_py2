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

"""Metrics for binary_health."""

from google.appengine.ext import deferred
from google.appengine.ext import ndb

from upvote.gae.datastore.models import base as base_models
from upvote.gae.datastore.models import bit9 as bit9_models
from upvote.gae.datastore.models import metrics as metrics_db
from upvote.gae.datastore.models import santa as santa_models
from upvote.gae.lib.analysis import api as analysis_api
from upvote.gae.lib.analysis import monitoring
from upvote.gae.lib.analysis.virustotal import constants as vt_constants
from upvote.gae.shared.common import settings
from upvote.shared import constants


def DeferLookupMetric(blockable_id, reason, queue=constants.TASK_QUEUE.METRICS):
  """Defer a task to collect binary health analysis."""
  if not settings.ENABLE_BINARY_ANALYSIS_PRECACHING:
    return

  deferred.defer(
      CollectLookup, blockable_id, reason, _queue=queue,
      _transactional=ndb.in_transaction())


def CollectLookup(blockable_id, reason):
  """Collect and store binary health analysis state for blockables.

  No errors are caught by this function so all NDB, monitoring, etc failures
  will be propagated to the caller.

  Args:
    blockable_id: str, The ID of the blockable for which analysis should be
        collected.
    reason: constants.ANALYSIS_REASON, The semantic significance of this metric
        collection. For example, it could be the first time Upvote has seen a
        blockable or a user could be voting on the blockable.

  Raises:
    ValueError: There is no Blockable associated with the provided blockable_id.
  """
  blockable = base_models.Blockable.get_by_id(blockable_id)
  if blockable is None:
    raise ValueError('Unknown Blockable: %s' % blockable_id)

  if isinstance(blockable, base_models.Binary):
    _CollectVirusTotalLookup(blockable_id, reason)


def _CollectVirusTotalLookup(blockable_id, reason):
  """Fetches VT analysis for the given blockable and saves the result."""
  results = analysis_api.VirusTotalLookup(blockable_id)

  response_code = results['response_code']
  analysis_state = (
      vt_constants.ANALYSIS_STATE.MAP_FROM_RESPONSE_CODE[response_code])

  positives = results.get('positives', -1)

  blockable = base_models.Blockable.get_by_id(blockable_id)

  metric = metrics_db.VirusTotalAnalysisMetric(
      blockable_id=blockable_id,
      platform=blockable.GetPlatformName(),
      analysis_state=analysis_state,
      analysis_reason=reason,
      positives=positives)
  metric.put()

  monitoring.virustotal_new_lookups.Increment(analysis_state)
