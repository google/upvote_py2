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

"""Models for storing certificate data."""

import datetime

from google.appengine.ext import ndb

from upvote.gae.bigquery import tables
from upvote.gae.datastore.models import base as base_models
from upvote.gae.datastore.models import mixin
from upvote.shared import constants


class Certificate(base_models.Blockable):
  """A codesigning certificate that has been encountered by Upvote."""

  @property
  def rule_type(self):
    return constants.RULE_TYPE.CERTIFICATE

  def InsertBigQueryRow(self, action, **kwargs):

    defaults = {
        'fingerprint': self.key.id(),
        'timestamp': datetime.datetime.utcnow(),
        'action': action,
        'state': self.state,
        'score': self.score}
    defaults.update(kwargs.copy())

    tables.CERTIFICATE.InsertRow(**defaults)


class Bit9Certificate(mixin.Bit9, Certificate):
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


class SantaCertificate(mixin.Santa, Certificate):
  """A certificate used to codesign at least one SantaBlockable.

  key = SHA-256 hash of certificate

  Attributes:
    common_name: str, cert Common Name.
    organization: str, Organization.
    organizational_unit: str, Organizational Unit.
    valid_from_dt: date, datetime that cert is valid from.
    valid_until_dt: date, datetime that cert is valid until.
  """
  common_name = ndb.StringProperty()
  organization = ndb.StringProperty()
  organizational_unit = ndb.StringProperty()
  valid_from_dt = ndb.DateTimeProperty()
  valid_until_dt = ndb.DateTimeProperty()

  def InsertBigQueryRow(self, action, **kwargs):

    defaults = {
        'not_before': self.valid_from_dt,
        'not_after': self.valid_until_dt,
        'common_name': self.common_name,
        'organization': self.organization,
        'organizational_unit': self.organizational_unit}
    defaults.update(kwargs.copy())

    super(SantaCertificate, self).InsertBigQueryRow(action, **defaults)
