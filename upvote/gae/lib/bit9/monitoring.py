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

from upvote.gae.utils import monitoring_utils
from upvote.monitoring import metrics


events_to_pull = monitoring_utils.Metric(metrics.BIT9_API.EVENTS_TO_PULL, long)
events_pulled = monitoring_utils.Counter(metrics.BIT9_API.EVENTS_PULLED)
events_to_process = monitoring_utils.Metric(
    metrics.BIT9_API.EVENTS_TO_PROCESS, long)
events_processed = monitoring_utils.Counter(metrics.BIT9_API.EVENTS_PROCESSED)
events_skipped = monitoring_utils.Counter(metrics.BIT9_API.EVENTS_SKIPPED)
pending_changes = monitoring_utils.Metric(metrics.BIT9_API.PENDING_CHANGES, long)

# Bit9 integration metrics
bit9_logins = monitoring_utils.SuccessFailureCounter(metrics.BIT9_API.BIT9_LOGINS)
bit9_qps = monitoring_utils.Counter(metrics.BIT9_API.BIT9_QPS)
bit9_requests = monitoring_utils.Counter(
    metrics.BIT9_API.BIT9_REQUESTS,
    fields=[('http_method', str), ('api_object', str), ('http_status', int)])
bit9_latency = monitoring_utils.LatencyMetric(
    metrics.BIT9_API.BIT9_LATENCY,
    fields=[('http_method', str), ('api_object', str)])
file_instances_missing = monitoring_utils.Counter(
    metrics.BIT9_API.FILE_INSTANCES_MISSING)
