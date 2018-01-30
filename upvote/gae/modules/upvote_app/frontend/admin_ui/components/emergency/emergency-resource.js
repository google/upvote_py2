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

goog.provide('upvote.admin.emergency.EmergencyResource');

goog.require('upvote.admin.app.constants');
goog.require('upvote.admin.lib.resources.buildResource');

goog.scope(() => {
const buildResource = upvote.admin.lib.resources.buildResource;


/** @const {string} */
const API_PREFIX = upvote.admin.app.constants.WEB_PREFIX + 'emergency/';


/** @export {function(!angular.$resource):!angular.Resource} */
upvote.admin.emergency.EmergencyResource = buildResource(API_PREFIX, {
  'setBigRedButton': {
    'method': 'POST',
    'params': {'bigRedButton': '@value'},
  },
  'setBigRedButtonStop1': {
    'method': 'POST',
    'params': {'bigRedButtonStop1': '@value'},
  },
  'setBigRedButtonStop2': {
    'method': 'POST',
    'params': {'bigRedButtonStop2': '@value'},
  },
  'setBigRedButtonGo1': {
    'method': 'POST',
    'params': {'bigRedButtonGo1': '@value'},
  },
  'setBigRedButtonGo2': {
    'method': 'POST',
    'params': {'bigRedButtonGo2': '@value'},
  }
});
});  // goog.scope
