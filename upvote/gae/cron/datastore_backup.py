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

"""Cron job for performing a scheduled Datastore backup."""

import datetime
import httplib
import json
import logging

import webapp2
from webapp2_extras import routes

import upvote.gae.lib.cloud.google_cloud_lib_fixer  # pylint: disable=unused-import
# pylint: disable=g-bad-import-order,g-import-not-at-top

# pylint: disable=g-import-not-at-top
try:
  from google.appengine.api import app_identity
except ImportError:
  app_identity = None

from google.appengine.api import urlfetch
from google.appengine.ext.ndb import metadata
from upvote.gae.utils import monitoring_utils
from upvote.gae.utils import env_utils
from upvote.gae.utils import handler_utils
from upvote.monitoring import metrics


_DATASTORE_BACKUPS = monitoring_utils.Counter(metrics.DATASTORE.BACKUPS)


class DatastoreBackup(handler_utils.CronJobHandler):
  """Handler for performing Datastore backups.

  NOTE: This backup does not pause writes to datastore during processing so the
  resulting backup does not reflect a snapshot of a single point in time. As
  such, there may be inconsistencies in the data across entity types.

  Based on:
    https://cloud.google.com/datastore/docs/schedule-export
  """

  def get(self):  # pylint: disable=g-bad-name

    # Only run backups in prod.
    if not env_utils.RunningInProd():
      logging.info('Datastore backups are only run in prod')
      return

    logging.info('Starting a new Datastore backup')

    access_token, _ = app_identity.get_access_token(
        'https://www.googleapis.com/auth/datastore')
    app_id = app_identity.get_application_id()

    # Configure a backup of all Datastore kinds, stored in a separate Cloud
    # Storage bucket for each day.
    output_url_prefix = 'gs://%s/%s/' % (
        env_utils.ENV.DATASTORE_BACKUP_BUCKET,
        datetime.datetime.utcnow().strftime('%Y_%m_%d'))
    kinds = [k for k in metadata.get_kinds() if not k.startswith('_')]
    request = {
        'project_id': app_id,
        'output_url_prefix': output_url_prefix,
        'entity_filter': {'kinds': kinds}
    }
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token
    }
    url = 'https://datastore.googleapis.com/v1/projects/%s:export' % app_id

    logging.info('Backing up %d kind(s) to %s', len(kinds), output_url_prefix)

    try:
      result = urlfetch.fetch(
          url=url,
          payload=json.dumps(request),
          method=urlfetch.POST,
          deadline=60,
          headers=headers)

      if result.status_code == httplib.OK:
        logging.info(result.content)
        _DATASTORE_BACKUPS.Increment()
      else:
        logging.warning(result.content)

      self.response.status_int = result.status_code

    except urlfetch.Error:
      logging.exception('Datastore backup failed')
      self.response.status_int = httplib.INTERNAL_SERVER_ERROR


ROUTES = routes.PathPrefixRoute('/datastore', [
    webapp2.Route('/backup', handler=DatastoreBackup),
])
