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

"""Module for interacting with the Bit9 REST API ORM."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import datetime

from absl import logging

from upvote.gae.lib.bit9 import constants
from upvote.gae.lib.bit9 import exceptions as excs
from upvote.gae.lib.bit9 import query
from upvote.gae.lib.bit9 import query_nodes


class Property(object):
  """Base class for API object properties."""

  _PYTHON_TYPE = None

  def __init__(self,
               api_name,
               repeated=False,
               allow_update=False,
               expands_to=None):
    self._name = api_name
    self._updatable = allow_update
    self._expands_to = expands_to
    self._repeated = repeated

    # This property will be set by the Model metaclass.
    self.model_cls_name = None

  @property
  def repeated(self):
    return self._repeated

  @property
  def updatable(self):
    return self._updatable

  @property
  def expandable(self):
    return self._expands_to is not None

  @property
  def expands_to(self):
    return self._expands_to

  @property
  def name(self):
    return self._name

  @classmethod
  def _is_valid_value(cls, val):
    return isinstance(val, cls._PYTHON_TYPE)

  @classmethod
  def raw_to_value(cls, raw):
    """Converts from the parsed JSON API format to the property format."""
    return raw

  @classmethod
  def value_to_raw(cls, val):
    """Converts from the property format to the parsed JSON API format."""
    if val is not None and not cls._is_valid_value(val):
      raise ValueError('Invalid {} value: {}'.format(cls.__name__, val))
    return val

  @classmethod
  def _value_to_query(cls, val):
    """Converts from the property format to the API query string format."""
    if val is None:
      return ''
    elif not cls._is_valid_value(val):
      raise ValueError('Invalid {} value: {}'.format(cls.__name__, val))
    else:
      return str(val)

  def __eq__(self, other):
    return query_nodes.FilterNode(self, ':', self._value_to_query(other))

  def __ne__(self, other):
    return query_nodes.FilterNode(self, '!', self._value_to_query(other))

  def __gt__(self, other):
    return query_nodes.FilterNode(self, '>', self._value_to_query(other))

  def __lt__(self, other):
    return query_nodes.FilterNode(self, '<', self._value_to_query(other))

  def __neg__(self):
    return query_nodes.OrderNode(self, ascending=False)

  def __repr__(self):
    return '{}.{}'.format(self.model_cls_name, self.name)


class StringProperty(Property):
  """A String type property."""

  _PYTHON_TYPE = basestring


class _IntegerProperty(Property):
  """Base class for integral properties."""

  _PYTHON_TYPE = int
  _BIT_LENGTH = None

  @classmethod
  def _is_valid_value(cls, val):
    try:
      return val.bit_length() <= cls._BIT_LENGTH
    except:  # pylint: disable=bare-except
      return False


class Int16Property(_IntegerProperty):
  """A 16-bit Integer type property."""

  _BIT_LENGTH = 16


class Int32Property(_IntegerProperty):
  """A 32-bit Integer type property."""

  _BIT_LENGTH = 32


class Int64Property(_IntegerProperty):
  """A 64-bit Integer String type property."""

  _BIT_LENGTH = 64


class DecimalProperty(Property):
  """A floating point type property."""

  _PYTHON_TYPE = float


class DoubleProperty(Property):
  """A double type property."""

  _PYTHON_TYPE = float


class BooleanProperty(Property):
  """A Boolean type property."""

  _PYTHON_TYPE = bool

  @classmethod
  def _value_to_query(cls, val):
    val = super(BooleanProperty, cls)._value_to_query(val)
    return str(val).lower()

  def __gt__(self, unused_other):
    raise excs.QueryError('Unsupported operation for boolean properties')

  def __lt__(self, unused_other):
    raise excs.QueryError('Unsupported operation for boolean properties')


class DateTimeProperty(Property):
  """A DateTime (timestamp) type property."""

  _PYTHON_TYPE = datetime.datetime

  _DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
  _DATETIME_FORMAT_USEC = '%Y-%m-%dT%H:%M:%S.%fZ'

  @classmethod
  def raw_to_value(cls, raw):
    if not raw:
      return None
    for format_ in (cls._DATETIME_FORMAT_USEC, cls._DATETIME_FORMAT):
      try:
        return datetime.datetime.strptime(raw, format_)
      except ValueError:
        pass
    raise ValueError("Invalid DateTime value: '{}'".format(raw))

  @classmethod
  def value_to_raw(cls, val):
    val = super(DateTimeProperty, cls).value_to_raw(val)
    # NOTE: This may up-sample date fields which don't provide a microsecond
    # value but it's better to gain precision than lose it.
    return val.strftime(cls._DATETIME_FORMAT_USEC)

  @classmethod
  def _value_to_query(cls, val):
    if val is None:
      return ''
    # Call the ValueToQuery on the base class for its type-checking.
    super(DateTimeProperty, cls)._value_to_query(val)
    return cls.value_to_raw(val)


class _MetaModel(type):
  """The metaclass for Model that enforces some required properties."""

  def __new__(mcs, name, parents, dct):
    assert len(parents) == 1
    if name != 'Model':
      if 'ROUTE' in dct:
        if not dct['ROUTE']:
          raise excs.Error('Models must define ROUTE property')
      elif not parents[0].ROUTE:
        raise excs.Error('Models must define ROUTE property')

    all_properties = {}
    for attr_name, attr in dct.iteritems():
      if isinstance(attr, Property):
        attr.model_cls_name = name
        all_properties[attr_name] = attr

    cls = super(_MetaModel, mcs).__new__(mcs, name, parents, dct)
    cls._KIND_MAP[name] = cls  # pylint: disable=protected-access
    cls._PROPERTIES = all_properties  # pylint: disable=protected-access

    return cls


class Model(object):
  """The base class for API object models."""

  __metaclass__ = _MetaModel

  # Subclasses must override. Should be the string name used in the API route
  # for the API object. e.g. /api/v1/ROUTE/my_id
  ROUTE = None

  # Dict common to all Models providing a mapping from Model name to Model
  # class. It is populated by the MetaClass when each Class is defined.
  _KIND_MAP = {}

  # Dict of all properties on the model mapping names to objects.
  # It is populated by the MetaClass when the Class is defined.
  _PROPERTIES = None

  def __init__(self, **kwargs):
    self._obj_dict = {}
    self._prefix = None

    for key, val in kwargs.iteritems():
      prop = self._get_and_validate_property(key)
      self._obj_dict[prop.name] = val

  @classmethod
  def from_dict(cls, obj_dict, prefix=None):
    inst = cls()
    if not isinstance(obj_dict, dict):
      raise ValueError('Invalid object dict: %s' % (obj_dict,))
    inst._obj_dict = obj_dict  # pylint: disable=protected-access
    inst._prefix = prefix  # pylint: disable=protected-access

    return inst

  @classmethod
  def _get_and_validate_property(cls,
                                 prop_or_name,
                                 require_updatable=False,
                                 require_expandable=False):
    """Converts the arg to a Property and ensures it's valid.

    Args:
      prop_or_name: Property or str, If str, it should be the name of a property
          on this Model. If Property, the function will verify that it belongs
          to this Model class.
      require_updatable: bool, Whether to perform an additional validation step
          to ensure the returned property is able to be updated.
      require_expandable: bool, Whether to perform an additional validation step
          to ensure the returned property is able to be expanded.

    Returns:
      The Property object provided or the one associated with the name that was
      provided.

    Raises:
      PropertyError: Some aspect of validation failed.
    """
    if isinstance(prop_or_name, Property):
      prop = prop_or_name
    else:
      prop = cls._PROPERTIES.get(prop_or_name)
      if prop is None:
        raise excs.PropertyError('Unknown property: {}'.format(prop_or_name))

    if not cls.is_valid_property(prop):
      raise excs.PropertyError(
          '{} cannot be used with {}'.format(prop, cls.__name__))
    elif require_updatable and not prop.updatable:
      raise excs.PropertyError(
          'Property {} may not be updated'.format(prop))
    elif require_expandable and not prop.expandable:
      raise excs.PropertyError(
          'Property {} may not be expanded'.format(prop))

    return prop

  @classmethod
  def is_valid_property(cls, prop):
    """Returns whether the Property is associated with this Model class."""
    return isinstance(prop, Property) and prop.model_cls_name == cls.__name__

  @classmethod
  def update(cls, id_, updated_properties, context):
    """Updates the fields of the entity with a given ID.

    NOTE: Because the Bit9 REST API doesn't offer an incremental update
    primitive, we use GET then POST here to construct such a primitive.

    Args:
      id_: str, The ID of the entity to update.
      updated_properties: dict<Property, Any> or dict<str, Any>, A mapping of
          the properties (or property names) to the values to which they should
          be updated.
      context: Context, The API context used to make the API requests.

    Returns:
      The response of the update call.
    """
    prop_map = {
        cls._get_and_validate_property(prop, require_updatable=True): val
        for prop, val in updated_properties.iteritems()}

    update_str = ', '.join(
        '{}="{}"'.format(prop, val) for prop, val in prop_map.iteritems())
    logging.info(
        'Updating %s object (id=%s): %s', cls.__name__, id_, update_str)

    obj = cls.get(id_, context)
    for prop, val in prop_map.iteritems():
      setattr(obj, prop.name, val)

    return obj.put(context)

  def put(self, context, extra_query_args=None):
    """Updates the current model instance or, if it didn't exist, creates it.

    Args:
      context: Context, The API context.
      extra_query_args: dict<str, Any>, Additional query args and values that
          will be provided to the API call. This is to support cases like
          "Computer" where the POST method accepts several non-property args
          like "resetCLIPassword" and "delete". See API docs for supported args.

    Returns:
      A new model instance representing the API response.
    """
    if extra_query_args:
      args = ['{}={}'.format(key, val)
              for key, val in extra_query_args.iteritems()]
    else:
      args = None

    response = context.ExecuteRequest(
        constants.METHOD.POST, api_route=self.ROUTE, query_args=args,
        data=self.to_raw_dict())
    return self.from_dict(response)

  @classmethod
  def get(cls, id_, context):
    """Gets an model instance by ID."""
    logging.info('GET %s object with ID %s', cls.__name__, id_)

    route = '{}/{}'.format(cls.ROUTE, id_)
    response = context.ExecuteRequest(constants.METHOD.GET, api_route=route)
    return cls.from_dict(response)

  @classmethod
  def delete(cls, id_, context):
    """Deletes a model instance by ID."""
    logging.info('DELETE %s object with ID %s', cls.__name__, id_)

    route = '{}/{}'.format(cls.ROUTE, id_)
    response = context.ExecuteRequest(constants.METHOD.DELETE, api_route=route)
    return cls.from_dict(response)

  @classmethod
  def query(cls):
    logging.info('Building %s query', cls.__name__)

    return query.Query(cls)

  def get_expand(self, prop_or_name):
    """Get a Model instance associated with an expanded property.

    Args:
      prop_or_name: Property or str, The expandable property (or property name)
          that should be expanded.

    Returns:
      If expanded data is present, an instance of the Model listed in the
      property's `expands_to` attribute.
      Else, None.

    Raises:
      PropertyError: An invalid or non-expandable property was provided OR the
          expands_to attribute on the property did not correspond to a known
          Model kind.
    """
    prop = self._get_and_validate_property(prop_or_name,
                                           require_expandable=True)

    expand_cls = self._KIND_MAP.get(prop.expands_to)
    if expand_cls is None:
      raise excs.PropertyError(
          'Cannot expand to unknown Model "%s"' % prop.expands_to)

    expanded_properties = (
        key
        for key in self._obj_dict.keys()
        if key.startswith(prop.name + '_'))
    if any(expanded_properties):
      return expand_cls.from_dict(self._obj_dict, prefix=prop.name)
    else:
      return None

  def to_dict(self):
    """Returns a dict representation of this instance."""
    return {
        name: getattr(self, name)
        for name in self._PROPERTIES.keys()}

  def to_raw_dict(self):
    """Returns a dict corresponding to this object's raw structure."""
    return {
        attr.name: attr.value_to_raw(getattr(self, name))
        for name, attr in self._PROPERTIES.iteritems()
        if attr.name in self._obj_dict}

  def _name_to_key(self, name):
    if self._prefix is not None:
      return '_'.join((self._prefix, name))
    else:
      return name

  def __getattribute__(self, name):
    attr = super(Model, self).__getattribute__(name)
    if isinstance(attr, Property):
      value = self._obj_dict.get(self._name_to_key(attr.name))
      return attr.raw_to_value(value)
    else:
      return attr

  def __setattr__(self, name, value):
    attr = self._PROPERTIES.get(name)
    if attr is None:
      super(Model, self).__setattr__(name, value)
    else:
      self._obj_dict[self._name_to_key(attr.name)] = attr.value_to_raw(value)

  def __eq__(self, other):
    return self.to_dict() == other.to_dict()

  def __ne__(self, other):
    return not self.__eq__(other)

  def __str__(self):
    return '{cls_name}(id={id_val}, ...)'.format(
        cls_name=type(self).__name__, id_val=getattr(self, 'id'))

  def __repr__(self):
    prop_lines = (
        '\n    {}={!r}'.format(name, val)
        for name, val in sorted(self.to_dict().iteritems()))
    return '{cls_name}({props})'.format(
        cls_name=type(self).__name__, props=','.join(prop_lines))
