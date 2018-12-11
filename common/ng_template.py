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

"""Invokes html2js and appends goog.provide.

https://www.npmjs.com/package/html2js
"""
import subprocess
import sys


def main(argv):
  # path to html2js
  html2js = argv[1]
  # A string that will be stripped out of every filename in the template id.
  strip_prefix = argv[2]
  # A string to prepend to template paths.
  prepend_prefix = argv[3]
  # Name of AngularJS module that needs to be created.
  module_name = argv[4]
  # goog module name.
  goog_provide = argv[5]
  # remaining args interpreted as html location.
  html_paths = argv[6:]

  result = ["goog.provide('{}');".format(goog_provide)]
  for src in html_paths:
    assert src.startswith(strip_prefix)
    js = subprocess.check_output([html2js, src, '--module', module_name],
                                 env={})
    template_name = prepend_prefix + src[len(strip_prefix):]
    js = js.replace(src, template_name)

    result.append(js)

  result.append("{} = angular.module('{}');".format(goog_provide, module_name))
  print '\n'.join(result)


if __name__ == '__main__':
  main(sys.argv)
