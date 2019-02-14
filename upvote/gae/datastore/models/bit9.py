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

"""Models specific to Bit9."""

from google.appengine.ext import ndb

from upvote.gae.datastore.models import base
from upvote.gae.datastore.models import mixin
from upvote.gae.datastore.models import rule as rule_models
from upvote.shared import constants


# Done for the sake of brevity.
_POLICY = constants.RULE_POLICY


class Bit9Binary(mixin.Bit9, base.Binary):
  """A file that has been blocked by Bit9.

  key = hash of blockable

  Attributes:
    # Selected properties corresponding to "File Properties" section in Bit9
    # Parity console "File Instance Details" view.
    description: str, Description.
    file_type: str, File Type.
    first_seen_name: str, First seen name.
    first_seen_date: datetime, First seen date.
    first_seen_computer:str, First seen host.
    first_seen_path: str, First seen path.
    detected_installer: bool, Whether Bit9's heuristic marked the binary as an
        installer.
    is_installer: bool, The binary's prescribed installer state.
    md5: str, MD5.
    product_version: str, Product version.
    sha1: str, SHA-1.
    company: str, Company associated with the file.
    file_size: int, File size, in bytes.
    file_catalog_id: str, The ID of the Bit9 fileCatalog entry corresponding to
        this blockable.
  """
  description = ndb.StringProperty()
  file_type = ndb.StringProperty()
  first_seen_name = ndb.StringProperty()
  first_seen_date = ndb.DateTimeProperty()
  first_seen_computer = ndb.StringProperty()
  first_seen_path = ndb.StringProperty()
  detected_installer = ndb.BooleanProperty(default=False)
  is_installer = ndb.BooleanProperty(default=False)

  md5 = ndb.StringProperty()
  product_version = ndb.StringProperty()
  sha1 = ndb.StringProperty()
  company = ndb.StringProperty()
  file_size = ndb.IntegerProperty()
  file_catalog_id = ndb.StringProperty()

  def InsertBigQueryRow(self, action, **kwargs):

    defaults = {'first_seen_file_name': self.first_seen_name}
    defaults.update(kwargs.copy())

    super(Bit9Binary, self).InsertBigQueryRow(action, **defaults)

  def CalculateInstallerState(self):
    """Returns the blockable's installer state as prescribed by Upvote.

    NOTE: Due to the ancestor query, this method will not reflect changes within
    uncommitted transactions.

    Returns:
      The current installer state prescribed by Upvote.
    """
    # pylint: disable=g-explicit-bool-comparison, singleton-comparison
    query = rule_models.Bit9Rule.query(
        rule_models.Bit9Rule.in_effect == True,
        ndb.OR(
            rule_models.Bit9Rule.policy == _POLICY.FORCE_INSTALLER,
            rule_models.Bit9Rule.policy == _POLICY.FORCE_NOT_INSTALLER),
        ancestor=self.key
    ).order(-rule_models.Bit9Rule.updated_dt)
    # pylint: enable=g-explicit-bool-comparison, singleton-comparison

    installer_rule = query.get()
    if installer_rule is None:
      return self.detected_installer
    else:
      return installer_rule.policy == _POLICY.FORCE_INSTALLER


class Bit9Certificate(mixin.Bit9, base.Certificate):
  """A certificate used to codesign at least one Bit9Binary.

  key = SHA-256 hash of certificate

  Attributes:
    valid_from_dt: date, datetime that cert is valid from.
    valid_until_dt: date, datetime that cert is valid until.
    parent_certificate_thumbprint: str, Thumbprint of parent certificate.
  """
  valid_from_dt = ndb.DateTimeProperty()
  valid_to_dt = ndb.DateTimeProperty()
  parent_certificate_thumbprint = ndb.StringProperty()

  def InsertBigQueryRow(self, action, **kwargs):

    defaults = {
        'not_before': self.valid_from_dt,
        'not_after': self.valid_to_dt,
        'common_name': 'Unknown',
        'organization': 'Unknown',
        'organizational_unit': 'Unknown'}
    defaults.update(kwargs.copy())

    super(Bit9Certificate, self).InsertBigQueryRow(action, **defaults)
