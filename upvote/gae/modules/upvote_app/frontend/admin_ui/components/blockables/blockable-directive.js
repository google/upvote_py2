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

goog.provide('upvote.admin.blockables.uvBlockableCard');
goog.provide('upvote.admin.blockables.uvBlockableHeader');
goog.provide('upvote.admin.blockables.uvBlockableListing');

goog.require('upvote.admin.app.constants');
goog.require('upvote.admin.lib.directives.buildCardDirective');

goog.scope(() => {
const buildCardDirective = upvote.admin.lib.directives.buildCardDirective;


/** @const {string} */
const TEMPLATE_PREFIX =
    upvote.admin.app.constants.STATIC_URL_PREFIX + 'components/blockables/';


/** @export {function():!angular.Directive} */
upvote.admin.blockables.uvBlockableCard =
    buildCardDirective(TEMPLATE_PREFIX + 'blockable-card.html');


/**
 * A directive for a blockable listing header.
 * @return {!angular.Directive} The directive definition.
 */
upvote.admin.blockables.uvBlockableHeader = () => {
  return {
    restrict: 'E',
    replace: true,
    scope: {'type': '='},
    templateUrl: TEMPLATE_PREFIX + 'blockable-header.html',
  };
};

/**
 * A directive for a blockable listing item.
 * @return {!angular.Directive} The directive definition.
 */
upvote.admin.blockables.uvBlockableListing = () => {
  return {
    restrict: 'E',
    scope: {'item': '=', 'onSelected': '&', 'type': '='},
    templateUrl: TEMPLATE_PREFIX + 'blockable-listing.html',
  };
};
});  // goog.scope
