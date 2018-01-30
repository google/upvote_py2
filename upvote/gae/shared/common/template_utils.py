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

"""Utilities for working with jinja2 templates."""

import os
import jinja2


_COMMON_TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), '../templates')


def _LoadTemplateAsResource(name):
  return open(os.path.join(_COMMON_TEMPLATE_PATH, name)).read()


def GetJinjaEnv():
  """Gets a jinja2 Environment which includes the desired path.

  Returns:
    A jinja2 Environment.
  """
  loader = jinja2.FunctionLoader(_LoadTemplateAsResource)
  return jinja2.Environment(
      loader=loader, autoescape=True, extensions=['jinja2.ext.autoescape'],
      finalize=lambda value: value or '', variable_start_string='[[',
      variable_end_string=']]')


def GetTemplate(template_name):
  """Gets a jinja2 Template instance for the given template name.

  Args:
    template_name: A string name for the template to retrieve.

  Returns:
    A jinja2 Template instance.

  Raises:
    TemplateNotFound: No template with the given name exists.
  """
  return _DEFAULT_JINJA_ENVIRONMENT.get_template(template_name)


# A Jinja2 environment which loads templates from the common directory.
_DEFAULT_JINJA_ENVIRONMENT = GetJinjaEnv()
