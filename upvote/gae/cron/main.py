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

from upvote.gae.cron import datastore_backup
from upvote.gae.cron import role_syncing

_ALL_ROUTES = [
    routes.PathPrefixRoute('/cron', [
        datastore_backup.ROUTES,
        role_syncing.ROUTES
    ]),
]

app = webapp2.WSGIApplication(routes=_ALL_ROUTES)
