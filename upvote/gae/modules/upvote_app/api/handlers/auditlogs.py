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

"""Views related to audit logs."""
import httplib
import logging

from upvote.gae.modules.upvote_app.api import monitoring
from upvote.gae.modules.upvote_app.api.handlers import base
from upvote.gae.shared.common import handlers
from upvote.gae.shared.models import base as base_db
from upvote.shared import constants


class AuditLogQueryHandler(base.BaseQueryHandler):
  """Handlers for querying Audit log entries."""

  MODEL_CLASS = base_db.AuditLog

  @property
  def RequestCounter(self):
    return monitoring.audit_log_requests

  @base.RequireCapability(constants.PERMISSIONS.VIEW_AUDIT_LOGS)
  @handlers.RecordRequest
  def get(self):
    self._Query()


class AuditLogHandler(base.BaseHandler):
  """Handlers for accessing individual Audit logs."""

  @base.RequireCapability(constants.PERMISSIONS.VIEW_AUDIT_LOGS)
  def get(self, log_id):
    logging.debug('AuditLog handler get method called for ID: ' + log_id)
    try:
      numeric_id = int(log_id)
    except ValueError:
      self.abort(httplib.BAD_REQUEST,
                 explanation='Audit Log ID must be numeric')
    else:
      log = base_db.AuditLog.get_by_id(numeric_id)
      if not log:
        self.abort(httplib.NOT_FOUND, explanation='Audit Log not found')
      else:
        self.respond_json(log)
