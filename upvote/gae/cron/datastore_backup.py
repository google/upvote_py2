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
import logging

import webapp2
from webapp2_extras import routes

import upvote.gae.lib.cloud.google_cloud_lib_fixer  # pylint: disable=unused-import
# pylint: disable=g-bad-import-order,g-import-not-at-top

from google.appengine.api import datastore
from google.appengine.api import taskqueue
from google.appengine.ext.ndb import metadata
from upvote.gae import settings
from upvote.shared import constants
from upvote.gae.utils import monitoring_utils
from upvote.gae.utils import env_utils
from upvote.gae.utils import handler_utils
from upvote.monitoring import metrics


_DATASTORE_BACKUPS = monitoring_utils.Counter(metrics.DATASTORE.BACKUPS)

_BACKUP_PREFIX = 'datastore_backup'


def _CreateDayString(dt=None):
  if not dt:
    dt = datetime.datetime.utcnow()
  return dt.strftime('%Y_%m_%d')


def _DailyBackupExists():
  expected_backup_name = '%s_%s' % (_BACKUP_PREFIX, _CreateDayString())
  query = datastore.Query(kind='_AE_Backup_Information', keys_only=True)
  query['name ='] = expected_backup_name
  return query.Get(1)


class DatastoreBackup(handler_utils.CronJobHandler):
  """Handler for performing Datastore backups.

  NOTE: This backup does not pause writes to datastore during processing so the
  resulting backup does not reflect a snapshot of a single point in time. As
  such, there may be inconsistencies in the data across entity types.
  """

  def get(self):  # pylint: disable=g-bad-name

    # Only run backups in prod.
    if not env_utils.RunningInProd():
      logging.info('Datastore backups are only run in prod')
      return

    # Only run one backup per day.
    if _DailyBackupExists():
      logging.info('A backup was already performed today.')
      return

    kinds = [k for k in metadata.get_kinds() if not k.startswith('_')]
    bucket = '%s/%s' % (settings.ENV.DATASTORE_BACKUP_BUCKET,
                        _CreateDayString())
    params = {
        'kind': kinds,
        'name': _BACKUP_PREFIX + '_',  # Date suffix is automatically added.
        'filesystem': 'gs',
        'gs_bucket_name': bucket,
        'queue': constants.TASK_QUEUE.BACKUP,
    }

    # Dump the backup onto a task queue. Don't worry about catching Exceptions,
    # anything that gets raised will be dealt with in UpvoteRequestHandler and
    # reported as a 500.
    logging.info('Starting a new Datastore backup')
    taskqueue.add(
        url='/_ah/datastore_admin/backup.create',
        params=params,
        target='ah-builtin-python-bundle',
        queue_name=constants.TASK_QUEUE.BACKUP)

    _DATASTORE_BACKUPS.Increment()


ROUTES = routes.PathPrefixRoute('/datastore', [
    webapp2.Route('/backup', handler=DatastoreBackup),
])
