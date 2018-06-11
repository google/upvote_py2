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

"""Common test utilities for bit9_api."""

from upvote.gae.modules.bit9_api import constants as bit9_constants
from upvote.gae.modules.bit9_api.api import api
from upvote.gae.shared.common import settings

# This giant dict is the combined default state for test data. It allows each of
# the generated entities to maintain consistency with the others e.g. keeping
# Event.policy_id, Computer.policy_id, and Policy.id consistent.
_ALL_DEFAULTS = {
    'certificate_id': 123,
    'certificate_state': bit9_constants.APPROVAL_STATE.UNAPPROVED,
    'cli_password': 'my-password',
    'company': 'goog',
    'computer_id': 456,
    'computer_name': settings.AD_DOMAIN + '\\my-computer',
    'date_created': '1970-01-01T00:00:00.000000Z',
    'description': 'description',
    'event_id': 444,
    'enforcement_level': 30,
    'file_catalog_id': 222,
    'file_flags': 0x0,
    'file_name': 'my-file.bat',
    'file_size': 30,
    'file_state': bit9_constants.APPROVAL_STATE.UNAPPROVED,
    'file_type': 'Script File',
    'md5': 'my-md5',
    'path_name': 'c:\\users\\foouser',
    'policy_id': 789,
    'policy_name': 'Lockdown',
    'product_name': 'the product',
    'product_version': 'the version',
    'publisher': 'goog',
    'publisher_id': 333,
    'publisher_state': bit9_constants.APPROVAL_STATE.UNAPPROVED,
    'sha1': 'my-insecure-sha',
    'sha256': 'my-more-secure-sha',
    'sha256_hash_type': bit9_constants.SHA256_TYPE.REGULAR,
    'subtype': bit9_constants.SUBTYPE.UNAPPROVED,
    'thumbprint': 'some_thumbprint',
    'thumbprint_algorithm': 'SHA1',
    'timestamp': '1970-01-01T00:00:00.000000Z',
    'received_timestamp': '1970-01-01T00:00:00.000000Z',
    'valid_from': '1970-01-01T00:00:00.000000Z',
    'valid_to': '1970-01-01T00:00:00.000000Z',
    'user_name': settings.AD_DOMAIN + '\\foouser',
    'users': settings.AD_DOMAIN + '\\foouser',
}

# These provides mappings of the names found in _ALL_DEFAULTS to the name for
# the actual property for the given Model for each Model class. All properties
# listed will be set on the created model.
_PROPERTY_MAP = {
    api.Computer: {
        'computer_id': 'id',
        'computer_name': 'name',
        'date_created': '',
        'policy_id': '',
        'users': '',
        'enforcement_level': '',
        'cli_password': ''},
    api.FileCatalog: {
        'file_catalog_id': 'id',
        'date_created': '',
        'path_name': '',
        'file_name': '',
        'computer_id': '',
        'md5': '',
        'sha1': '',
        'sha256': '',
        'sha256_hash_type': '',
        'file_type': '',
        'file_size': '',
        'product_name': '',
        'publisher': '',
        'company': '',
        'product_version': '',
        'file_state': '',
        'publisher_state': '',
        'certificate_state': '',
        'file_flags': '',
        'publisher_id': '',
        'certificate_id': ''},
    api.Certificate: {
        'certificate_id': 'id',
        'certificate_state': '',
        'thumbprint': '',
        'thumbprint_algorithm': '',
        'valid_from': '',
        'valid_to': ''},
    api.Event: {
        'event_id': 'id',
        'timestamp': '',
        'received_timestamp': '',
        'subtype': '',
        'computer_id': '',
        'policy_id': '',
        'file_catalog_id': '',
        'file_name': '',
        'path_name': '',
        'user_name': ''},
    api.Policy: {
        'policy_id': 'id',
        'name': 'policy_name',
        'enforcement_level': ''},
}


def Expand(target_entity, property_, expanded_entity):
  """Merges one entity into another as if it were expanded on property_.

  Args:
    target_entity: api.Model
    property_: api.Property, The property for which the expand should be
        generated.
    expanded_entity: api.Model

  Returns:
    A copy of the target_entity object with the expanded contents of
    expanded_entity.
  """
  # pylint: disable=protected-access
  expand_dict = {
      '{}_{}'.format(property_.name, key): value
      for key, value in expanded_entity._obj_dict.iteritems()}
  entity_copy = target_entity.__class__()
  entity_copy._obj_dict.update(target_entity._obj_dict)
  entity_copy._obj_dict.update(expand_dict)
  return entity_copy
  # pylint: enable=protected-access


def _CreateModel(model_cls, **kwargs):
  defaults = {
      other or name: _ALL_DEFAULTS[name]
      for name, other in _PROPERTY_MAP[model_cls].iteritems()}
  defaults.update(kwargs)
  return model_cls(**defaults)


def CreateFileCatalog(**kwargs):
  return _CreateModel(api.FileCatalog, **kwargs)


def CreateComputer(**kwargs):
  return _CreateModel(api.Computer, **kwargs)


def CreateEvent(**kwargs):
  return _CreateModel(api.Event, **kwargs)


def CreatePolicy(**kwargs):
  return _CreateModel(api.Policy, **kwargs)


def CreateCertificate(**kwargs):
  return _CreateModel(api.Certificate, **kwargs)


def LinkSigningChain(*certs):
  """Sets up the parent cert ID property values for a chain of certs."""
  for i, cert in enumerate(certs):
    if i == len(certs) - 1:
      cert.parent_certificate_id = 0
    else:
      cert.parent_certificate_id = certs[i + 1].id
