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
"""Tests for the template_utils module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import jinja2
import six

from upvote.gae.utils import template_utils
from absl.testing import absltest


class RenderTemplateTest(absltest.TestCase):

  def testInvalidTemplate(self):
    with self.assertRaises(jinja2.TemplateNotFound):
      template_utils._RenderTemplate('test', 'no_bueno.html')

  def testSuccess_Simple(self):
    expected_content = 'this is a simple template'
    actual_content = template_utils._RenderTemplate('test', 'simple.html')
    self.assertEqual(expected_content, actual_content)

  def testSuccess_Complex(self):
    expected_content = 'this is a complex template: 12345'
    actual_content = template_utils._RenderTemplate(
        'test', 'complex.html', contents=12345)
    self.assertEqual(expected_content, actual_content)

  def testUndefinedError(self):
    with self.assertRaises(jinja2.UndefinedError):
      template_utils._RenderTemplate('test', 'complex.html')


class RenderWebTemplateTest(absltest.TestCase):

  def testInvalidTemplate(self):
    with self.assertRaises(jinja2.TemplateNotFound):
      template_utils.RenderWebTemplate('no_bueno.html')

  def testSuccess(self):
    content = template_utils.RenderWebTemplate(
        'user-index.html', debug=False, username='asdf')
    self.assertIsInstance(content, six.text_type)


class RenderEmailTemplateTest(absltest.TestCase):

  def testInvalidTemplate(self):
    with self.assertRaises(jinja2.TemplateNotFound):
      template_utils.RenderEmailTemplate('no_bueno.html')

  def testSuccess(self):
    content = template_utils.RenderEmailTemplate(
        'exemption_expired.html', device_hostname='aaa', upvote_hostname='bbb')
    self.assertIsInstance(content, six.text_type)


if __name__ == '__main__':
  absltest.main()
