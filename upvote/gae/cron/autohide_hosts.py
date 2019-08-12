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

"""Cron job for marking likely-inactive Hosts as hidden."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import datetime
import itertools
import logging

import webapp2
from webapp2_extras import routes

from google.appengine.ext import deferred
from google.appengine.ext import ndb

from upvote.gae import settings
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import host as host_models
from upvote.gae.utils import handler_utils
from upvote.shared import constants


@ndb.transactional
def _AutohideSantaHost(host_key):
  host = host_key.get()
  host.hidden = True
  host.put()


def _AutohideSantaHosts():
  """Marks all inactive SantaHosts as hidden."""
  now = datetime.datetime.utcnow()
  cutoff = now - datetime.timedelta(days=settings.HOST_INACTIVITY_THRESHOLD)

  # Query for all likely-inactive, non-hidden SantaHosts.
  # pylint: disable=g-explicit-bool-comparison, singleton-comparison
  query = host_models.SantaHost.query(
      host_models.SantaHost.last_postflight_dt < cutoff,
      host_models.SantaHost.hidden == False)
  # pylint: enable=g-explicit-bool-comparison, singleton-comparison
  query = datastore_utils.Paginate(query, keys_only=True)

  # Defer an individual task for each SantaHost to mark as hidden.
  for host_key in itertools.chain.from_iterable(query):
    deferred.defer(
        _AutohideSantaHost, host_key, _queue=constants.TASK_QUEUE.DEFAULT)


class AutohideHosts(handler_utils.CronJobHandler):

  def get(self):
    logging.info('Marking inactive Hosts as hidden...')

    # For now, only autohide SantaHosts, as their activity/inactivity can be
    # reasonably determined via preflight/postflight timestamps. Bit9Hosts only
    # have last_event_dt, which would result in a lot of false positives.
    deferred.defer(_AutohideSantaHosts, _queue=constants.TASK_QUEUE.DEFAULT)


ROUTES = routes.PathPrefixRoute('/hosts', [
    webapp2.Route('/autohide', handler=AutohideHosts),
])
