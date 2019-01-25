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

"""Monitoring metrics for the upvote_app AppEngine module."""

from upvote.gae.utils import monitoring_utils
from upvote.monitoring import metrics


blockable_requests = (
    monitoring_utils.RequestCounter(metrics.UPVOTE_APP.BLOCKABLE_REQUESTS))

event_requests = monitoring_utils.RequestCounter(metrics.UPVOTE_APP.EVENT_REQUESTS)

host_requests = monitoring_utils.RequestCounter(metrics.UPVOTE_APP.HOST_REQUESTS)

lookup_requests = monitoring_utils.RequestCounter(
    metrics.UPVOTE_APP.LOOKUP_REQUESTS)

user_requests = monitoring_utils.RequestCounter(metrics.UPVOTE_APP.USER_REQUESTS)

report_requests = monitoring_utils.RequestCounter(
    metrics.UPVOTE_APP.REPORT_REQUESTS)

rule_requests = monitoring_utils.RequestCounter(metrics.UPVOTE_APP.RULE_REQUESTS)

setting_requests = monitoring_utils.RequestCounter(
    metrics.UPVOTE_APP.SETTING_REQUESTS)

vote_requests = monitoring_utils.RequestCounter(metrics.UPVOTE_APP.VOTE_REQUESTS)
