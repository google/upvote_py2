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

"""API handler for actions related to data export tasks."""

import httplib
import logging

import upvote.gae.shared.common.google_cloud_lib_fixer  # pylint: disable=unused-import
# pylint: disable=g-bad-import-order,g-import-not-at-top
from google.cloud import bigquery

from upvote.gae.modules.upvote_app.api.handlers import base
from upvote.gae.modules.upvote_app.lib import bigquery_schema
from upvote.gae.shared.common import settings
from upvote.shared import constants


class InitializeBigqueryStreaming(base.BaseHandler):

  @base.RequireCapability('admin')
  def get(self):
    if not settings.ENV.ENABLE_BIGQUERY_STREAMING:
      return

    self.response.headers['Content-Type'] = 'text/plain'

    bq_client = bigquery.Client()
    dataset = bq_client.dataset(constants.GAE_STREAMING_DATASET)

    logging.info('Creating dataset: "%s"', dataset.name)
    self.response.write('Creating dataset: "%s"...' % dataset.name)
    if not dataset.exists():
      try:
        dataset.create()
      except Exception as e:  # pylint: disable=broad-except
        self.response.write('FAILED: %s\n' % str(e))
        raise
      else:
        self.response.write('SUCCESS\n')
    else:
      self.response.write('EXISTS\n')

    for table_name, schema in bigquery_schema.TABLE_SCHEMAS.iteritems():
      table = dataset.table(table_name, schema=schema)

      logging.info('Creating table: "%s"', table.name)
      self.response.write('Creating table: "%s"...' % table.name)
      if not table.exists():
        try:
          table.create()
        except Exception as e:  # pylint: disable=broad-except
          self.response.write('FAILED: %s\n' % str(e))
          raise
        else:
          self.response.write('SUCCESS\n')
      else:
        self.response.write('EXISTS\n')

    self.response.write('\nOK!')
    self.response.set_status(httplib.OK)
