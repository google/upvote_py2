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

"""Application-wide configuration."""

import datetime
import logging

from upvote.gae.shared.models import santa
from upvote.shared import constants


_CRITICAL_MAC_OS_CERT_HASHES = [

    # Google Certificate for Chrome
    '345a8e098bd04794aaeefda8c9ef56a0bf3d3706d67d35bc0e23f11bb3bffce5',

    # Apple Software Signing for macOS 10.10, 10.11, 10.12, and 10.13
    '2aa4b9973b7ba07add447ee4da8b5337c3ee2c3a991911e80e7282e8a751fc32',

    # Google Certificate for Santa
    '33b9aee3b089c922952c9240a40a0daa271bebf192cf3f7d964722e8f2170e48']


def PopulateDatastore():  # pylint: disable=g-bad-name
  """Populates the datastore with any critical entities."""

  for critical_hash in _CRITICAL_MAC_OS_CERT_HASHES:

    cert = santa.SantaCertificate.get_by_id(critical_hash)

    if not cert:
      cert = santa.SantaCertificate(
          id=critical_hash, id_type=constants.ID_TYPE.SHA256)
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


PopulateDatastore()
