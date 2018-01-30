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

"""API Main URL Handling."""

import webapp2
from webapp2_extras import routes

from upvote.gae.modules.santa_api import sync
from upvote.gae.shared.common import handlers


UUID_RE = r'[0-9A-F]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}'

app = webapp2.WSGIApplication([
    # Warmup
    webapp2.Route(r'/_ah/warmup', handlers.AckHandler),
    routes.PathPrefixRoute(
        r'/api/santa',
        [
            # Verifies the module is reachable.
            webapp2.Route(r'/ack', handlers.AckHandler),

            # Santa API. All handlers expect a UUID in the URL
            webapp2.Route(r'/xsrf/<:%s>' % UUID_RE, sync.XsrfHandler),
            webapp2.Route(r'/preflight/<:%s>' % UUID_RE, sync.PreflightHandler),
            webapp2.Route(r'/logupload/<:%s>' % UUID_RE, sync.LogUploadHandler),
            webapp2.Route(r'/eventupload/<:%s>' % UUID_RE,
                          sync.EventUploadHandler),
            webapp2.Route(r'/binaryupload/<:%s>' % UUID_RE,
                          sync.BinaryUploadHandler),
            webapp2.Route(r'/ruledownload/<:%s>' % UUID_RE,
                          sync.RuleDownloadHandler),
            webapp2.Route(r'/postflight/<:%s>' % UUID_RE,
                          sync.PostflightHandler),
        ]),
])

handlers.CreateErrorHandlersForApplications([app])
