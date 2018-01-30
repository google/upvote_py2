// Copyright 2017 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

goog.provide('upvote.admin.lib.directives.buildCardDirective');
goog.provide('upvote.admin.lib.directives.buildListingDirective');

goog.scope(() => {


/**
 * Builds a card directive.
 *
 * @param {string} directiveTemplate The url of the directive template.
 * @return {function():!angular.Directive}
 */
upvote.admin.lib.directives.buildCardDirective = (directiveTemplate) => {
  return () => {
    return {
      restrict: 'E',
      templateUrl: directiveTemplate,
      scope: {'card': '=', 'constant': '=', 'onChange': '&'},
    };
  };
};
});  // goog.scope
