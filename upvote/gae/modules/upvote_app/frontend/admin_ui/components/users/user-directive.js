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

goog.provide('upvote.admin.users.uvUserCard');

goog.require('upvote.admin.app.constants');
goog.require('upvote.admin.lib.directives.buildCardDirective');

goog.scope(() => {
const buildCardDirective = upvote.admin.lib.directives.buildCardDirective;


/** @const {string} */
const TEMPLATE_PREFIX =
    upvote.admin.app.constants.STATIC_URL_PREFIX + 'components/users/';


/** @export {function():!angular.Directive} */
upvote.admin.users.uvUserCard =
    buildCardDirective(TEMPLATE_PREFIX + 'user-card.html');
});  // goog.scope
