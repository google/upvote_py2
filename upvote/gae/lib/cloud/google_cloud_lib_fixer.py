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

"""Allows import and use of google-cloud-python libraries on App Engine."""
import sys
import warnings

# pylint: disable=g-bad-import-order,g-import-not-at-top

# Fix up default 'google' module to enable import of all google
# cloud libraries.
import os
import google
google.__path__.extend(
    os.path.join(path, 'google')
    for path in sys.path
    if 'gcloud_' in path)

# Patch urllib3 to use URLFetch because native sockets degrade the success rates
# of external connections, notably Cloud KMS interactions.
from requests_toolbelt.adapters import appengine
appengine.monkeypatch()
warnings.filterwarnings('ignore', message=r'urllib3 is using URLFetch.*')

# Pre-populate the monotonic module so the normal one doesn't try to import
# ctypes (which isn't available on GAE Standard environment).
from upvote.gae.lib.cloud import fake_monotonic
sys.modules['monotonic'] = fake_monotonic
