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

"""Monitoring metric constants to be used throughout Upvote."""


UPVOTE = 'upvote/'


class Metric(object):

  def __init__(self, metric_name, display_name):
    self.metric_name = metric_name
    self.display_name = display_name

  def __str__(self):
    return self.metric_name


class Namespace(object):
  """A heirarchical namespace for metrics."""

  def __init__(self, prefix, tuples):

    self.metrics = []

    for t in tuples:
      metric = Metric(prefix + t[0], t[1])
      setattr(self, t[0].upper(), metric)
      self.metrics.append(metric)

    setattr(self, 'ALL', self.metrics)

  def __iter__(self):
    for metric in self.metrics:
      yield metric


class UpvoteNamespace(Namespace):

  def __init__(self, prefix, tuples):
    super(UpvoteNamespace, self).__init__(UPVOTE + prefix, tuples)


SANTA_API = UpvoteNamespace('santa_api/', [
    ('preflight_requests', 'Preflight Requests'),
    ('event_upload_requests', 'Event Upload Requests'),
    ('log_upload_requests', 'Log Upload Requests'),
    ('binary_upload_requests', 'Binary Upload Requests'),
    ('rule_download_requests', 'Rule Download Requests'),
    ('postflight_requests', 'Postflight Requests')])


BIT9_ARBITER = UpvoteNamespace('bit9_arbiter/', [
    ('block_events_pending', 'Block Events Pending')])


BIT9_API = UpvoteNamespace('bit9_api/', [
    ('events_to_pull', 'Events To Pull'),
    ('events_pulled', 'Events Pulled'),
    ('events_to_process', 'Events To Process'),
    ('events_processed', 'Events Processed'),
    ('pending_changes', 'Pending Changes'),
    ('bit9_logins', 'Bit9 Logins'),
    ('bit9_qps', 'Bit9 QPS'),
    ('bit9_requests', 'Bit9 Requests'),
    ('bit9_latency', 'Bit9 Latency')])


BIT9_REST_API = UpvoteNamespace('bit9_rest_api/', [
    ('qps', 'QPS'),
    ('requests', 'Requests'),
    ('latency', 'Latency')])


UPVOTE_APP = UpvoteNamespace('upvote_app/', [
    ('blockable_requests', 'Blockable Requested'),
    ('constant_requests', 'Constant Requested'),
    ('event_requests', 'Event Requested'),
    ('host_requests', 'Host Requested'),
    ('lookup_requests', 'Lookup Requested'),
    ('report_requests', 'Report Requested'),
    ('rule_requests', 'Rule Requested'),
    ('setting_requests', 'Setting Requested'),
    ('user_requests', 'User Requested'),
    ('vote_requests', 'Vote Requested')])


ANALYSIS = UpvoteNamespace('analysis/', [
    ('virustotal_requests', 'VirusTotal Requests'),
    ('virustotal_new_lookups', 'VirusTotal Results for New Blockables')])


BIGQUERY = UpvoteNamespace('bigquery/', [
    ('rows_to_persist', 'Rows To Persist'),
    ('rows_persisted', 'Rows Persisted'),
    ('rows_to_stream', 'Rows To Stream'),
    ('rows_streamed', 'Rows Streamed')])


RPC_SERVER = Namespace('/rpc/server/', [
    ('count', 'RPC Query Count'),
    ('error_count', 'RPC Error Count'),
    ('server_latency', 'RPC Query Latency')])


PRESENCE = Namespace('/presence/', [
    ('found', 'Presence')])
