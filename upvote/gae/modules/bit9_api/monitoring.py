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

"""Monitoring metrics for the bit9_api AppEngine module."""

from upvote.gae.shared.common import monitoring
from upvote.monitoring import metrics


events_to_pull = monitoring.Metric(metrics.BIT9_API.EVENTS_TO_PULL, long)
events_pulled = monitoring.Counter(metrics.BIT9_API.EVENTS_PULLED)
events_to_process = monitoring.Metric(
    metrics.BIT9_API.EVENTS_TO_PROCESS, long)
events_processed = monitoring.Counter(metrics.BIT9_API.EVENTS_PROCESSED)
pending_changes = monitoring.Metric(metrics.BIT9_API.PENDING_CHANGES, long)
