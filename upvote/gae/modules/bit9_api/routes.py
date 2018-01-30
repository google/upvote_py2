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

"""Route definitions for the bit9_api module."""


import webapp2
from webapp2_extras import routes

from upvote.gae.modules.bit9_api import cron
from upvote.gae.modules.bit9_api import handlers
from upvote.gae.shared.common import handlers as common_handlers


bit9 = webapp2.WSGIApplication(routes=[

    webapp2.Route('/_ah/warmup', handler=common_handlers.AckHandler),

    routes.PathPrefixRoute('/api/bit9', [

        webapp2.Route('/ack', handler=common_handlers.AckHandler),

        routes.PathPrefixRoute('/cron', [
            webapp2.Route(
                '/commit-pending-change-sets',
                handler=cron.CommitAllChangeSets),
            webapp2.Route(
                '/update-policies',
                handler=cron.UpdateBit9Policies),
            webapp2.Route(
                '/count-events-to-pull',
                handler=cron.CountEventsToPull),
            webapp2.Route(
                '/pull-events',
                handler=cron.PullEvents),
            webapp2.Route(
                '/count-events-to-process',
                handler=cron.CountEventsToProcess),
            webapp2.Route(
                '/process-events',
                handler=cron.ProcessEvents),
        ]),

        webapp2.Route(
            '/host-health-information',
            handler=handlers.GetHostHealthInformation),
        webapp2.Route(
            '/associated-hosts/<user_id>',
            handler=handlers.AssociatedHosts),
        webapp2.Route(
            '/commit-change-set/<blockable_id>',
            handler=handlers.CommitBlockableChangeSet),
    ]),
])

common_handlers.CreateErrorHandlersForApplications([bit9])
