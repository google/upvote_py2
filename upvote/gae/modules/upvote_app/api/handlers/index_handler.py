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

"""A module for the index handler."""
from google.appengine.api import users

from upvote.gae.shared.common import handlers
from upvote.gae.shared.common import template_utils


class IndexHandler(handlers.UpvoteRequestHandler):
  """The handler for the main Angular template."""

  class IndexPageVersion(object):
    ADMIN = 'admin-index.html'
    USER = 'user-index.html'

  def _Get(self, template_name):
    debug_text = self.request.get('debug', '0')
    try:
      debug = bool(int(debug_text))
    except ValueError:
      debug = False
    template_context = {
        'debug': debug,
        'username': users.get_current_user(),
    }
    # Write the jinja2 template rendering to the handler's repsonse.
    response_string = template_utils.GetTemplate(
        template_name).render(template_context)
    self.response.set_status(200)

    self.response.write(response_string)

  def GetAdmin(self, *args, **kwargs):
    return self._Get(self.IndexPageVersion.ADMIN)

  def GetUser(self, *args, **kwargs):
    return self._Get(self.IndexPageVersion.USER)

