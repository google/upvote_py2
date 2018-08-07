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

"""Taskqueue utility methods."""

from google.appengine.api import taskqueue

from google.appengine.ext import deferred

from upvote.shared import constants


_COMMIT_KEY = 'DO-COMMIT'
_DELAYED_TASKS = {}


def QueueSize(queue=constants.TASK_QUEUE.DEFAULT, deadline=10):
  queue = taskqueue.Queue(name=queue)
  queue_stats = queue.fetch_statistics(deadline=deadline)
  return queue_stats.tasks


def CappedDefer(
    callable_obj, max_size, queue=constants.TASK_QUEUE.DEFAULT, *args,
    **kwargs):
  can_defer = QueueSize(queue=queue) < max_size
  if can_defer:
    deferred.defer(callable_obj, _queue=queue, *args, **kwargs)
  return can_defer
