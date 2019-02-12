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

"""Client for interacting with the VirusTotal binary service."""

import json
import logging
import urllib

from google.appengine.api import urlfetch

from upvote.gae.datastore.models import singleton
from upvote.gae.lib.analysis.virustotal import constants
from upvote.gae.utils import memcache_utils

_RESULT_CACHE_TIMEOUT = 4. * 60 * 60  # 4 hours

_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
_KNOWN_RESPONSE_CODES = set(
    constants.ANALYSIS_STATE.MAP_FROM_RESPONSE_CODE.keys())


class Error(Exception):
  """Base Error for the VirusTotal client."""


class ResponseError(Error):
  """Indicates an invalid response from the VirusTotal API."""


def _CreateLookupCacheKey(func, prefix, args, unused_kwargs=None):
  """Generate a unique key from the Lookup function and its arguments."""
  prefix = prefix or func.__name__
  binary_hash = args[0] or ''
  return '%s|%s' % (prefix, binary_hash)


def _OnlyCacheAnalyzed(unused_call_args, unused_call_kwargs, call_return):
  if not isinstance(call_return, dict):
    return False
  response_code = call_return.get('response_code')
  state = constants.ANALYSIS_STATE.MAP_FROM_RESPONSE_CODE.get(response_code)
  return state == constants.ANALYSIS_STATE.ANALYZED


@memcache_utils.ConditionallyCached(
    key_name='VirusTotalLookup',
    create_key_func=_CreateLookupCacheKey,
    expire_time=_RESULT_CACHE_TIMEOUT,
    cache_predicate=_OnlyCacheAnalyzed)
def Lookup(binary_hash):
  """Queries VirusTotal for the given binary hash.

  Args:
    binary_hash: SHA256 hash of the binary in question.

  Returns:
    Dict containing information VirusTotal knows about the binary.
  """
  # Decrypt our VirusTotal API key. If something blows up, just let the
  # exception bubble up to binary_health._PerformLookup().
  vt_auth = singleton.VirusTotalApiAuth.GetInstance()

  payload = urllib.urlencode({
      'apikey': vt_auth.api_key,
      'resource': binary_hash})

  # Perform the VirusTotal query.
  response_obj = urlfetch.fetch(
      url=_REPORT_URL,
      payload=payload,
      method=urlfetch.POST,
      headers={'Content-Type': 'application/x-www-form-urlencoded'},
      deadline=15,
      validate_certificate=True)

  # Parse the response content into a dict.
  response_dict = {}
  try:
    json_dict = json.loads(response_obj.content)
  except ValueError:
    logging.error(
        'Bad VT response (HTTP %s): %s', response_obj.status_code,
        response_obj.content)
    raise ResponseError(
        'Failed to parse API response: %s' % response_obj.content)
  else:
    response_dict.update(json_dict)

  # Include verbose response from VT API when unknown response code given.
  if ('response_code' in response_dict and
      response_dict['response_code'] not in _KNOWN_RESPONSE_CODES):
    logging.warn('VirusTotal Error: %s', response_dict['verbose_msg'])

  # Only return scans from trusted antivirus scanners.
  scans = response_dict.get('scans')
  if scans:
    response_dict['scans'] = {
        vendor: scans[vendor]
        for vendor in constants.TRUSTED_AV_VENDORS
        if vendor in scans}
    response_dict['positives'] = sum(
        scan.get('detected') for scan in response_dict['scans'].values())
    response_dict['total'] = len(response_dict['scans'])

  return response_dict
