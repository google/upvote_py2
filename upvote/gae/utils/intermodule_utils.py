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

"""Provides methods for GAE modules to communicate among one another."""

import functools
import httplib
import logging
import urllib
import urlparse

from google.appengine.api import modules
from google.appengine.api import urlfetch

from upvote.gae.shared.common import settings

_REDIRECT_ATTEMPTS = 5


def _FetchWithRedirects(url, redirect_attempts=_REDIRECT_ATTEMPTS, **kwargs):
  if not redirect_attempts:
    raise urlfetch.Error('Too many redirects')

  logging.debug(
      'Fetching with %s redirects remaining: %s', redirect_attempts, url)
  try:
    response = urlfetch.fetch(url, **kwargs)
  except urlfetch.Error:
    logging.exception('Error encountered while submitting request to %s', url)
    raise
  else:
    if response.status_code == httplib.FOUND:
      redirect_url = response.headers.get('Location')
      return _FetchWithRedirects(
          redirect_url, redirect_attempts=redirect_attempts - 1, **kwargs)
    else:
      return response


def _CreateRequestURL(module, path):
  """Composes the appropriate request URL for a given AppEngine module.

  Exists primarily for easier unit testing.

  Args:
    module: The name of the AppEngine module.
    path: The path portion of the URL.

  Returns:
    A fully-composed request URL.
  """
  parts = ('https', modules.get_hostname(module=module), path, '', '')
  return urlparse.urlunsplit(parts)


def SubmitIntermoduleRequest(module, path, data=None, deadline=None):
  """Helper method for making calls from one GAE module to another.


  Args:
    module: GAE module name, as found in the corresponding .yaml file.
    path: The path portion of the intermodule URL.
    data: Optional data dictionary to be submitted. Omitting this dict results
        in a GET being performed. Including it results in a POST.
    deadline: int, If provided, the maximum number of seconds to wait for the
        request.

  Returns:
    The urlfetch response object which contains:
      status_code (int)
      headers (dict)
      content (str)
      json_content (JSON-parsed obj)

  Raises:
    urlfetch.Error: An error occurred with the request.
  """
  request_url = _CreateRequestURL(module, path)

  payload = urllib.urlencode(data, doseq=True) if data is not None else None
  method = urlfetch.GET if payload is None else urlfetch.POST

  logging.info('%s %s', 'GET' if data is None else 'POST', request_url)

  response = _FetchWithRedirects(
      request_url,
      method=method,
      headers={
          'Content-Type': 'application/x-www-form-urlencoded',
          'Host': urlparse.urlsplit(request_url).netloc,
          'X-URLFetch-Service-Id': 'APPSPOT',
      },
      payload=payload,
      deadline=deadline,
      follow_redirects=False)
  return response


