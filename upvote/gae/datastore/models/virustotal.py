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

"""NDB models for VirusTotal interactions."""

from common.cloud_kms import kms_ndb
from upvote.gae.datastore import utils

_KEY_LOC = 'global'
_KEY_RING = 'ring'
_KEY_NAME = 'virustotal'


class VirusTotalApiAuth(utils.Singleton):
  """The VirusTotal API key.

  This class is intended to be a singleton as there should only be a single
  VirusTotal API key associated with a project.
  """
  api_key = kms_ndb.EncryptedBlobProperty(_KEY_NAME, _KEY_RING, _KEY_LOC)
