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

"""Utilities for defining Upvote settings."""

import logging
import os

import six

# pylint: disable=g-import-not-at-top
try:
  from google.appengine.api import app_identity
except ImportError:
  app_identity = None

_ALL_ENVS = set()


class Error(Exception):
  """Base exception class."""


class UnknownEnvironment(Error):
  """Raised when the current environment cannot be determined."""


class _MetaEnv(type):
  """A metaclass that records all subclasses of DefaultEnv."""

  def __new__(mcs, name, parents, dct):
    cls = super(_MetaEnv, mcs).__new__(mcs, name, parents, dct)
    if name != 'DefaultEnv':
      _ALL_ENVS.add(cls)
    return cls


class DefaultEnv(six.with_metaclass(_MetaEnv)):
  """The base class for environment namespaces."""


def CurrentEnvironment():
  """Returns the current environment the app is running in.

  Returns:
    The DefaultEnv subclass associated with the current environment.

  Raises:
    UnknownEnvironment: if the environment cannot be determined.
  """
  logging.info('Attempting to determine current environment')

  # Check the DEFAULT_VERSION_HOSTNAME first.
  logging.info('Checking DEFAULT_VERSION_HOSTNAME')
  if 'DEFAULT_VERSION_HOSTNAME' in os.environ:
    hostname = app_identity.get_default_version_hostname()
    logging.info('DEFAULT_VERSION_HOSTNAME is %s', hostname)
    for env in _ALL_ENVS:
      if env.HOSTNAME == hostname:
        return env
  else:
    logging.info('DEFAULT_VERSION_HOSTNAME not present')

  # Fall back to APPLICATION_ID.
  logging.info('Checking APPLICATION_ID')
  if 'APPLICATION_ID' in os.environ:
    app_id = app_identity.get_application_id()
    logging.info('APPLICATION_ID is %s', app_id)
    for env in _ALL_ENVS:
      if env.PROJECT_ID == app_id:
        return env
  else:
    logging.info('APPLICATION_ID not present')

  # Well shit...
  logging.warning('Unable to determine the current environment')
  raise UnknownEnvironment
