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

# Lint as: python2, python3
"""Test utils common to Upvote GAE."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import datetime

import mock
from six.moves import range


class PicklableMock(mock.MagicMock):
  """A Mock class that can be pickled.

  This code was taken from the example at:
  https://github.com/testing-cabal/mock/issues/139#issuecomment-122128815
  """

  def __reduce__(self):
    return (mock.Mock, ())


def GetSequentialTimes(count=2):
  now = datetime.datetime.utcnow()
  return [now + datetime.timedelta(seconds=i) for i in range(count)]
