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

"""Monitoring metrics for generated statistics."""

from upvote.gae.shared.common import monitoring
from upvote.monitoring import metrics


rows_to_persist = monitoring.Metric(metrics.BIGQUERY.ROWS_TO_PERSIST, long)
rows_to_stream = monitoring.Metric(metrics.BIGQUERY.ROWS_TO_STREAM, long)
rows_streamed = monitoring.Counter(metrics.BIGQUERY.ROWS_STREAMED)
