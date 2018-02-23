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

"""Model representations of BigQuery rows for streaming data."""

from google.appengine.ext import deferred
from google.appengine.ext import ndb
from google.appengine.ext.ndb import polymodel

from upvote.gae.datastore import utils as model_utils
from upvote.gae.shared.common import settings
from upvote.gae.shared.common import monitoring
from upvote.monitoring import metrics
from upvote.shared import constants


_PERSISTED_METRIC = monitoring.Counter(metrics.BIGQUERY.ROWS_PERSISTED)


class BigQueryRow(polymodel.PolyModel):
  """Base class for all rows being persisted for BigQuery streaming."""

  @classmethod
  def DeferCreate(cls, **row_params):
    if not settings.ENV.ENABLE_BIGQUERY_STREAMING:
      return
    deferred.defer(
        cls.Create,
        _queue=constants.TASK_QUEUE.BQ_PERSISTENCE,
        _transactional=ndb.in_transaction(),
        **row_params)

  @classmethod
  def Create(cls, **row_params):
    if not settings.ENV.ENABLE_BIGQUERY_STREAMING:
      return
    return cls.CreateAsync(**row_params).get_result()

  @classmethod
  def CreateAsync(cls, **row_params):
    if not settings.ENV.ENABLE_BIGQUERY_STREAMING:
      return model_utils.GetNoOpFuture()

    row = cls(**row_params)
    future = row.put_async()
    _PERSISTED_METRIC.Increment()
    return future


class VoteRow(BigQueryRow):
  """Model representation of a row in the Vote table."""

  sha256 = ndb.StringProperty(required=True)
  timestamp = ndb.DateTimeProperty(required=True)
  upvote = ndb.BooleanProperty(required=True)
  weight = ndb.IntegerProperty(required=True)
  platform = ndb.StringProperty(
      required=True, choices=constants.PLATFORM.SET_ALL)
  target_type = ndb.StringProperty(
      required=True, choices=constants.RULE_TYPE.SET_ALL)
  voter = ndb.StringProperty(required=True)


class HostRow(BigQueryRow):
  """Model representation of a row in the Host table."""

  device_id = ndb.StringProperty(required=True)
  timestamp = ndb.DateTimeProperty(required=True)
  action = ndb.StringProperty(
      required=True, choices=constants.HOST_ACTION.SET_ALL)
  hostname = ndb.StringProperty()
  platform = ndb.StringProperty(
      required=True, choices=constants.PLATFORM.SET_ALL)
  users = ndb.StringProperty(repeated=True)
  mode = ndb.StringProperty(required=True, choices=constants.HOST_MODE.SET_ALL)
  comment = ndb.StringProperty()


class BinaryRow(BigQueryRow):
  """Model representation of a row in the Binary table."""

  sha256 = ndb.StringProperty(required=True)
  timestamp = ndb.DateTimeProperty(required=True)
  action = ndb.StringProperty(
      required=True, choices=constants.BLOCK_ACTION.SET_ALL)
  state = ndb.StringProperty(required=True, choices=constants.STATE.SET_ALL)
  score = ndb.IntegerProperty(required=True)
  platform = ndb.StringProperty(
      required=True, choices=constants.PLATFORM.SET_ALL)
  client = ndb.StringProperty(required=True, choices=constants.CLIENT.SET_ALL)
  first_seen_file_name = ndb.StringProperty()
  cert_fingerprint = ndb.StringProperty()
  comment = ndb.StringProperty()


class ExecutionRow(BigQueryRow):
  """Model representation of a row in the Execution table."""

  sha256 = ndb.StringProperty(required=True)
  device_id = ndb.StringProperty(required=True)
  timestamp = ndb.DateTimeProperty(required=True)
  platform = ndb.StringProperty(
      required=True, choices=constants.PLATFORM.SET_ALL)
  client = ndb.StringProperty(required=True, choices=constants.CLIENT.SET_ALL)
  bundle_path = ndb.StringProperty()
  file_path = ndb.StringProperty()
  file_name = ndb.StringProperty()
  executing_user = ndb.StringProperty()
  associated_users = ndb.StringProperty(repeated=True)
  decision = ndb.StringProperty(
      required=True, choices=constants.EVENT_TYPE.SET_ALL)
  comment = ndb.StringProperty()


class CertificateRow(BigQueryRow):
  """Model representation of a row in the Certificate table."""

  fingerprint = ndb.StringProperty(required=True)
  timestamp = ndb.DateTimeProperty(required=True)
  action = ndb.StringProperty(
      required=True, choices=constants.BLOCK_ACTION.SET_ALL)
  common_name = ndb.StringProperty()
  organization = ndb.StringProperty()
  organizational_unit = ndb.StringProperty()
  not_before = ndb.DateTimeProperty()
  not_after = ndb.DateTimeProperty()
  state = ndb.StringProperty(required=True, choices=constants.STATE.SET_ALL)
  score = ndb.IntegerProperty(required=True)
  comment = ndb.StringProperty()


class BundleRow(BigQueryRow):
  """Model representation of a row in the Bundle table."""

  bundle_hash = ndb.StringProperty(required=True)
  timestamp = ndb.DateTimeProperty(required=True)
  action = ndb.StringProperty(
      required=True, choices=constants.BLOCK_ACTION.SET_ALL)
  bundle_id = ndb.StringProperty()
  version = ndb.StringProperty()
  state = ndb.StringProperty(required=True, choices=constants.STATE.SET_ALL)
  score = ndb.IntegerProperty(required=True)
  comment = ndb.StringProperty()


class BundleBinaryRow(BigQueryRow):
  """Model representation of a row in the BundleBinary table."""

  bundle_hash = ndb.StringProperty(required=True)
  sha256 = ndb.StringProperty(required=True)
  timestamp = ndb.DateTimeProperty(required=True)
  action = ndb.StringProperty(
      required=True, choices=constants.BLOCK_ACTION.SET_ALL)
  cert_fingerprint = ndb.StringProperty()
  relative_path = ndb.StringProperty()
  file_name = ndb.StringProperty()


class UserRow(BigQueryRow):
  """Model representation of a row in the User table."""
  email = ndb.StringProperty(required=True)
  timestamp = ndb.DateTimeProperty(required=True)
  action = ndb.StringProperty(
      required=True, choices=constants.USER_ACTION.SET_ALL)
  roles = ndb.StringProperty(repeated=True)
  comment = ndb.StringProperty()
