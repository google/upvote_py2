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

"""Model definitions for Upvote metrics."""

from google.appengine.ext import ndb
from google.appengine.ext.ndb import polymodel

from upvote.gae.lib.analysis.virustotal import constants as vt_constants
from upvote.shared import constants


class Metric(polymodel.PolyModel):
  """The base class for metrics."""
  recorded_dt = ndb.DateTimeProperty(auto_now_add=True)


class BinaryHealthMetric(Metric):
  """A metric storing blockable binary health analysis state.

  Attributes:
    blockable_id: The ID of the blockable that was analyzed.
    platform: The platform of the analyzed blockable.
    analysis_reason: The reason why the analysis was collected. The reasons
        correspond to logical events in the blockable's lifetime in Upvote
            (e.g. blockable created, blockable voted on, etc.).
  """
  blockable_id = ndb.StringProperty()
  platform = ndb.StringProperty(choices=constants.PLATFORM.SET_ALL)
  analysis_reason = ndb.StringProperty(
      choices=constants.ANALYSIS_REASON.SET_ALL)


class VirusTotalAnalysisMetric(BinaryHealthMetric):
  """A metric storing the VirusTotal analysis state for blockables.

  Attributes:
    analysis_state: The state of analysis in VirusTotal e.g. whether the
        blockable has been analyzed, is in progress, or has not been analyzed.
    positives: The number of AV reports that flagged the blockable as malware or
        -1 if no analysis available.
  """
  analysis_state = ndb.StringProperty(
      choices=vt_constants.ANALYSIS_STATE.SET_ALL)
  positives = ndb.IntegerProperty()
