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

"""Models and functions for defining whitelist/blacklist rules."""

from upvote.gae.datastore.models import santa
from upvote.shared import constants


def EnsureCriticalRules(sha256_list):
  """Pre-populates Datastore with any critical Rule entities."""
  for sha256 in sha256_list:

    cert = santa.SantaCertificate.get_by_id(sha256)

    if not cert:
      cert = santa.SantaCertificate(id=sha256, id_type=constants.ID_TYPE.SHA256)
      cert.put()

    # Check for at least one matching SantaRule.
    rule_missing = santa.SantaRule.query(
        ancestor=cert.key).get(keys_only=True) is None

    # Doesn't exist? Add it!
    if rule_missing:
      santa.SantaRule(
          parent=cert.key,
          rule_type=constants.RULE_TYPE.CERTIFICATE,
          policy=constants.RULE_POLICY.WHITELIST).put()

