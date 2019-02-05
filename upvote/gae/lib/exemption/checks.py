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

"""Module containing the checks that are run before granting an exemption."""

import collections
import functools
import logging

from upvote.gae.datastore.models import exemption as exemption_models
from upvote.gae.datastore.models import host as host_models
from upvote.gae.datastore.models import utils as model_utils
from upvote.gae.lib.exemption import monitoring
from upvote.gae.utils import env_utils
from upvote.gae.utils import group_utils
from upvote.shared import constants


# Done for brevity.
_STATE = constants.EXEMPTION_STATE


# Define a 'Result' namedtuple and set default values.
Result = collections.namedtuple('Result', ['name', 'state', 'detail'])
Result.__new__.__defaults__ = ('UNKNOWN', _STATE.DENIED, None)  # pylint: disable=protected-access


def PolicyCheck(check_func):
  """Decorator for wrapping policy checking functions.

  Args:
    check_func: The policy check function being decorated.

  Returns:
    A wrapped version of 'check_func'.
  """
  @functools.wraps(check_func)
  def _Wrapper(exm_key):
    """Wrapper of the given policy checking function.

    Args:
      exm_key: The NDB Key of the Exemption in question.

    Returns:
      A Result namedtuple.
    """
    check_func_name = check_func.__name__
    logging.info('Executing %s()', check_func_name)

    state, detail = check_func(exm_key)

    logging.info(
        '%s() returned %s%s', check_func_name, state,
        ' (%s)' % detail if detail else '')
    monitoring.policy_check_outcomes.Increment(state)
    return Result(check_func_name, state, detail)

  return _Wrapper


