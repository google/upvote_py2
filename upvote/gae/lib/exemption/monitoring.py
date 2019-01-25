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

"""Monitoring metrics for the Exemption system."""

from upvote.gae.utils import monitoring_utils
from upvote.monitoring import metrics


enforcement_errors = monitoring_utils.Counter(metrics.EXEMPTION.ENFORCEMENT_ERRORS)
expired_exemptions = monitoring_utils.Metric(
    metrics.EXEMPTION.EXPIRED_EXEMPTIONS, long)
policy_check_outcomes = monitoring_utils.Counter(
    metrics.EXEMPTION.POLICY_CHECK_OUTCOMES, fields=[(u'outcome', str)])
processing_errors = monitoring_utils.Counter(metrics.EXEMPTION.PROCESSING_ERRORS)
requested_exemptions = monitoring_utils.Metric(
    metrics.EXEMPTION.REQUESTED_EXEMPTIONS, long)
revocation_errors = monitoring_utils.Counter(metrics.EXEMPTION.REVOCATION_ERRORS)
state_changes = monitoring_utils.Counter(
    metrics.EXEMPTION.STATE_CHANGES, fields=[(u'state', str)])
