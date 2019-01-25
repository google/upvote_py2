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

import functools
import logging
import os
import jinja2


def _LoadTemplate(template_subdir, template_name):
  template_path = os.path.join(
      os.path.dirname(__file__), '../templates', template_subdir, template_name)
  logging.info('Loading template: %s/%s', template_subdir, template_name)
  return open(template_path).read() if os.path.isfile(template_path) else None


def _RenderTemplate(template_subdir, template_name, **context):
  """Loads a template file and renders it to unicode.

  Args:
    template_subdir: The subdirectory in gae/templates containing the template
        file.
    template_name: The name of the template file.
    **context: Optional key/value pairs to render into the template.

  Returns:
    The given template file rendered with the given context as a unicode string.

  Raises:
    jinja2.TemplateNotFound: if the given template file doesn't exist.
  """
  # Create a partial loading function, which will return the contents of the
  # template given just the template name.
  loading_func = functools.partial(_LoadTemplate, template_subdir)

  # Construct an Environment and retrieve the Template.
  env = jinja2.Environment(
      loader=jinja2.FunctionLoader(loading_func),
      autoescape=True,
      extensions=['jinja2.ext.autoescape'],
      finalize=lambda value: value or '',
      variable_start_string='[[',
      variable_end_string=']]',
      undefined=jinja2.StrictUndefined)
  template = env.get_template(template_name)

  # Render the template with the provided context.
  return template.render(**context)


def RenderWebTemplate(template_name, **context):
  return _RenderTemplate('web', template_name, **context)


def RenderEmailTemplate(template_name, **context):
  return _RenderTemplate('email', template_name, **context)
