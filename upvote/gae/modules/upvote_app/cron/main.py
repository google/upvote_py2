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

"""Routing for cron tasks."""

import webapp2

from webapp2_extras import routes

from upvote.gae.modules.upvote_app.cron import export
from upvote.gae.modules.upvote_app.cron import roles


app = webapp2.WSGIApplication([
    # Handlers
    routes.PathPrefixRoute('/cron', [

        # Backup
        routes.PathPrefixRoute('/export', [
            webapp2.Route(
                '/datastore-to-gcs', handler=export.DatastoreToGCS),
            webapp2.Route(
                '/stream-to-bigquery', handler=export.StreamToBigQuery),
            webapp2.Route(
                '/count-rows-to-persist', handler=export.CountRowsToPersist),
            webapp2.Route(
                '/count-rows-to-stream', handler=export.CountRowsToStream)
        ]),

        # Roles
        routes.PathPrefixRoute('/roles', [
            webapp2.Route('/sync', handler=roles.SyncRoles),
            webapp2.Route('/lock-it-down', handler=roles.LockItDown),
            webapp2.Route('/monitor-it', handler=roles.MonitorIt),
            webapp2.Route('/lock-spider', handler=roles.LockSpider),
        ]),
    ])
])
