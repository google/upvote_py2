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

"""A script to translate the Bit9 API description page to API Models.

NOTE: This is _NOT_ intended on being a consistently maintained part of the API.
It's merely a convenience to avoid the tedium of translating the docs to Bit9
Model classes.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import collections

import bs4

from absl import app
from absl import flags

from upvote.gae.modules.bit9_api.api import utils

FLAGS = flags.FLAGS

flags.DEFINE_string(
    'docs_path', None,
    'The path to the HTML file containing the Bit9 REST API documentation.')
flags.DEFINE_list(
    'objects_to_output', [u'approvalRequest', u'fileInstance', u'fileCatalog',
                          u'publisher', u'fileRule', u'certificate', u'policy',
                          u'event', u'computer'],
    'The list of Bit9 API object names for which models should be generated.')


_TYPE_TO_PROPERTY = {
    'String': 'StringProperty',
    'DateTime': 'DateTimeProperty',
    'Int16': 'Int16Property',
    'Int32': 'Int32Property',
    'Int64': 'Int64Property',
    'Boolean': 'BooleanProperty',
    'Decimal': 'DecimalProperty',
    'Double': 'DoubleProperty',
}


def _FindFromNext(start_tag, search_tag):
  """Finds a sibling that either is or contains a given tag.

  Because the REST API HTML in bedlam is non-heirarchical (i.e. blocks are flat,
  not nested), we need to search through all sibling nodes in the tree instead
  of child nodes.

  Args:
    start_tag: bs4.element.Tag, The tag from which siblings should be searched.
    search_tag: str, The name of the tag to look for.

  Returns:
    (parent_tag, target_tag), both bs4.element.Tags. parent_tag is the sibling
    tag of start_tag that encloses the tag matching search_tag. target_tag is
    the tag that matches the search_tag type exactly.

    parent_tag can be the same as target_tag if it's the one matching
    search_tag.

    If the search_tag is not found, (None, None) is returned.
  """
  tag = start_tag.next_sibling
  while tag is not None:
    if isinstance(tag, bs4.element.Tag):
      if tag.name == search_tag:
        return tag, tag
      child_matches = tag.find_all(search_tag)
      if child_matches:
        return tag, child_matches[0]
    tag = tag.next_sibling

  if tag is None:
    return None, None


def CapitalizeFirstLetter(s):
  return s[0].upper() + s[1:] if s else s


def GetApiInfo(html_file, objects_to_output):
  """Extracts the API info from the API description page's source.

  Info format:
      {
        <api_name>: {
          'api_name': str,
          'properties': {
            <prop_name>: {
              'name': str
              'type': str
              'updateable': bool
              'expands_to': str
            },
            ...
          }
        },
        ...
      }

  Args:
    html_file: str or file, The HTML source of the Bit9 REST API description
        page.
    objects_to_output: list<str>, The list of objects to be generated. This
        allows the function to ignore expands_to clauses for types that will be
        absent from the resulting API.

  Returns:
    An info dict of the format described above.
  """
  soup = bs4.BeautifulSoup(html_file, 'html.parser')
  obj_apis = soup.find_all('h3', class_='apiTitle')
  objs = collections.OrderedDict()
  for api in obj_apis:
    api_name = api['id']
    objs[api_name] = {
        'api_name': api_name, 'properties': collections.OrderedDict()}

    tag, header = _FindFromNext(api, 'h4')
    if 'All Object' not in header.text:
      del objs[api_name]
      continue
    tag, table = _FindFromNext(tag, 'table')

    properties = objs[api_name]['properties']
    for row in table.find_all('tr')[1:]:
      name, type_, description = row.find_all('td')

      expands_to = None
      if 'This is foreign key' in description.text:
        obj_name = description.find('code').text
        if obj_name in objects_to_output:
          expands_to = CapitalizeFirstLetter(obj_name)

      properties[name.text] = {
          'name': name.text, 'type': type_.text, 'updateable': False,
          'expands_to': expands_to}

    tag, header = _FindFromNext(tag, 'h4')
    if 'Properties modifiable' not in header.text:
      continue
    tag, table = _FindFromNext(tag, 'table')

    for row in table.find_all('tr')[1:]:
      name, _, _ = row.find_all('td')
      if name.text in properties:
        properties[name.text]['updateable'] = True

  return objs


def GenerateProperty(property_dict):
  """Returns a property field declaration for the provided property."""
  prop_name = utils.camel_to_snake_case_with_acronyms(property_dict['name'])
  type_name = _TYPE_TO_PROPERTY.get(property_dict['type'])
  if type_name is None:
    return '  # Skipped %s' % prop_name
  args = ["'%s'" % property_dict['name']]
  if property_dict['updateable']:
    args.append('allow_update=True')
  if property_dict['expands_to'] is not None:
    args.append('expands_to=\'%s\'' % property_dict['expands_to'])
  return '  %s = model.%s(%s)' % (prop_name, type_name, ', '.join(args))


def GenerateModel(obj_dict):
  route = obj_dict['api_name']
  class_name = CapitalizeFirstLetter(route)
  lines = [
      'class %s(model.Model):' % class_name,
      '  ROUTE = \'%s\'' % route,
      ''] + [GenerateProperty(prop) for prop in obj_dict['properties'].values()]
  return '\n'.join(lines)


def GenerateModels(info_dict):
  return '\n\n\n'.join(GenerateModel(dict_) for dict_ in info_dict.values())


def GenerateHeader():
  return '\n'.join([
      ''.center(80, '#'),
      ' Generated by build_from_docs.py '.center(80, '#'),
      ''.center(80, '#')])


def main(unused_argv):
  with open(FLAGS.docs_path, 'r') as docs_file:
    api_objs = GetApiInfo(docs_file, FLAGS.objects_to_output)

  # Filter out objects not present in objects_to_output.
  obj_names = FLAGS.objects_to_output
  filtered_objs = collections.OrderedDict()
  for name, dict_ in api_objs.iteritems():
    if name in obj_names:
      filtered_objs[name] = dict_

  print(GenerateHeader())
  print('\n')
  print(GenerateModels(filtered_objs))


if __name__ == '__main__':
  flags.mark_flag_as_required('docs_path')
  app.run()
