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

"""Utils for the Upvote Bit9 API."""

from common import context

from upvote.gae.modules.bit9_api.api import api  # pylint: disable=line-too-long
from upvote.gae.shared.common import settings
from upvote.gae.datastore.models import bit9


def ExpandHostname(bit9_hostname):
  """Add the AD hostname suffix if the provided one isn't fully-qualified."""
  bit9_hostname = bit9_hostname.lower()

  if '.' in bit9_hostname:
    return bit9_hostname
  return '.'.join((bit9_hostname, settings.AD_HOSTNAME.lower()))


@context.LazyProxy
def CONTEXT():  # pylint: disable=g-bad-name
  auth = bit9.Bit9ApiAuth.GetInstance()
  return api.Context(settings.ENV.BIT9_REST_URL, auth.api_key, 30)
