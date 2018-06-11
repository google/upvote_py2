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

"""Central module for submitting all binary health queries."""

import logging

from upvote.gae.lib.analysis import monitoring
from upvote.gae.lib.analysis.virustotal import virustotal_client


class Error(Exception):
  """Module-level base Exception."""


class LookupFailure(Error):
  """Raised when a binary health lookup fails for some reason."""


def _PerformLookup(name, lookup_func, metric, *args, **kwargs):
  """Wrapper method for performing all binary health lookups.

  Args:
    name: Informal name of the lookup service being used.
    lookup_func: Function of the lookup service to be called.
    metric: SuccessFailureCounter for tracking the lookup outcomes.
    *args: Any args required of lookup_func.
    **kwargs: Any kwargs required of lookup_func.

  Returns:
    A dict which will contain all information that the lookup service knows
    about the given binary.

  Raises:
    LookupFailure: if the call to the lookup service fails for any reason.
  """
  try:
    logging.debug('Submitting binary health query to %s...', name)
    response_dict = lookup_func(*args, **kwargs)
    metric.Success()
    logging.debug('Binary health query to %s returned: %s', name, response_dict)
    return response_dict
  except Exception as e:  # pylint: disable=broad-except
    logging.exception(e)
    metric.Failure()
    raise LookupFailure('Error encountered while performing %s lookup' % name)




def VirusTotalLookup(binary_hash):
  """Performs a binary health lookup using VirusTotal.

  Args:
    binary_hash: The hash of the binary to check.

  Returns:
    A dict which will contain all information that VirusTotal knows about the
    given binary.

  Raises:
    LookupFailure: if the call to VirusTotal fails for any reason.
  """
  return _PerformLookup(
      'VirusTotal', virustotal_client.Lookup, monitoring.virustotal_requests,
      binary_hash)
