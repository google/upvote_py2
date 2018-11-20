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

"""Tests for the template_utils module."""

import jinja2

from upvote.gae.shared.common import template_utils
from absl.testing import absltest


class TemplateUtilsTest(absltest.TestCase):

  def testGetTemplate(self):
    # Actually just load one of our templates.
    template = template_utils.GetTemplate('admin-index.html')
    self.assertIn('ng-app', template.render())

  def testGetJinjaEnv(self):
    env = template_utils.GetJinjaEnv()
    self.assertIsInstance(env, jinja2.Environment)


if __name__ == '__main__':
  absltest.main()
