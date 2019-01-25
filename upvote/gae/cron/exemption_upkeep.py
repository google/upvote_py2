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

"""Cron jobs which perform various Exemption maintenance tasks."""

import datetime
import logging

import webapp2
from webapp2_extras import routes

from google.appengine.ext import deferred

from upvote.gae import settings
from upvote.gae.datastore.models import exemption as exemption_models
from upvote.gae.datastore.models import utils as model_utils
from upvote.gae.lib.exemption import api as exemption_api
from upvote.gae.lib.exemption import notify
from upvote.gae.lib.exemption import monitoring
from upvote.gae.utils import group_utils
from upvote.gae.utils import handler_utils
from upvote.gae.utils import user_utils
from upvote.shared import constants


# Done for the sake of brevity.
EXEMPTION_STATE = constants.EXEMPTION_STATE



class ProcessExemptions(handler_utils.CronJobHandler):
  """Handler for processing exemptions."""

  def get(self):
    logging.info('Processing Exemptions...')

    exm_query = exemption_models.Exemption.query(
        exemption_models.Exemption.state == EXEMPTION_STATE.REQUESTED)

    exm_count = 0
    for exm in exm_query:
      deferred.defer(
          exemption_api.Process, exm.key,
          _queue=constants.TASK_QUEUE.EXEMPTIONS)
      exm_count += 1

    monitoring.requested_exemptions.Set(exm_count)
    logging.info('Deferred %d Exemption(s) for processing', exm_count)


def _NotifyExpirationsInRange(start_dt, end_dt):
  """Sends an email for all APPROVED Exemptions that expire in the given range.

  Args:
    start_dt: The starting datetime of the expiration window.
    end_dt: The ending datetime of the expiration window.
  """
  # Query for the Keys of all Exemptions that expire in the given range.
  exm_query = exemption_models.Exemption.query(
      exemption_models.Exemption.state == EXEMPTION_STATE.APPROVED,
      exemption_models.Exemption.deactivation_dt >= start_dt,
      exemption_models.Exemption.deactivation_dt < end_dt)
  exm_keys = exm_query.fetch(keys_only=True)

  for exm_key in exm_keys:
    notify.SendExpirationEmail(exm_key)


class NotifyUpcomingExpirations(handler_utils.CronJobHandler):
  """Handler for notifying users of upcoming exemption expirations."""

  def get(self):

    now = datetime.datetime.utcnow()

    # Notify all users whose Exemptions now have less than a week left, in order
    # to give reasonable advance warning (e.g. long weekends, holidays, etc).
    one_week_start_dt = now + datetime.timedelta(days=7, hours=-1)
    one_week_end_dt = now + datetime.timedelta(days=7)

    # Notify all users whose Exemptions now have less that 24 hours left. This
    # will act as a final reminder, and will also ensure that even users who
    # choose a 1-day Exemption will get an email warning (for what it's worth).
    one_day_start_dt = now + datetime.timedelta(days=1, hours=-1)
    one_day_end_dt = now + datetime.timedelta(days=1)

    tuples = [
        (one_week_start_dt, one_week_end_dt),
        (one_day_start_dt, one_day_end_dt)]

    # Defer a task for each batch of notifications.
    for start_dt, end_dt in tuples:
      deferred.defer(
          _NotifyExpirationsInRange, start_dt, end_dt,
          _queue=constants.TASK_QUEUE.EXEMPTIONS)


class ExpireExemptions(handler_utils.CronJobHandler):
  """Handler for expiring exemptions."""

  def get(self):
    logging.info('Expiring Exemptions...')

    now = datetime.datetime.utcnow()
    exm_query = exemption_models.Exemption.query(
        exemption_models.Exemption.state == EXEMPTION_STATE.APPROVED,
        exemption_models.Exemption.deactivation_dt <= now)

    exm_count = 0
    for exm in exm_query:
      deferred.defer(
          exemption_api.Expire, exm.key,
          _queue=constants.TASK_QUEUE.EXEMPTIONS)
      exm_count += 1

    monitoring.expired_exemptions.Set(exm_count)
    logging.info('Deferred %d Exemption(s) for expiration', exm_count)


ROUTES = routes.PathPrefixRoute('/exemptions', [
    webapp2.Route('/process', handler=ProcessExemptions),
    webapp2.Route(
        '/notify-upcoming-expirations',
        handler=NotifyUpcomingExpirations),
    webapp2.Route('/expire', handler=ExpireExemptions),
])
