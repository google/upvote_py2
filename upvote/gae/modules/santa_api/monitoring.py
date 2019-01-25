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

"""Monitoring metrics for the santa_api AppEngine module."""

from upvote.gae.utils import monitoring_utils
from upvote.monitoring import metrics


preflight_requests = monitoring_utils.RequestCounter(
    metrics.SANTA_API.PREFLIGHT_REQUESTS)

event_upload_requests = monitoring_utils.RequestCounter(
    metrics.SANTA_API.EVENT_UPLOAD_REQUESTS)

rule_download_requests = monitoring_utils.RequestCounter(
    metrics.SANTA_API.RULE_DOWNLOAD_REQUESTS)

postflight_requests = monitoring_utils.RequestCounter(
    metrics.SANTA_API.POSTFLIGHT_REQUESTS)
