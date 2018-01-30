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

goog.provide('upvote.admin.lib.resources.buildQueryResource');
goog.provide('upvote.admin.lib.resources.buildResource');

goog.scope(() => {


/**
 * @param {string} url
 * @param {!Object<string,angular.ResourceAction>=} opt_actions
 * @return {function(!angular.$resource):!angular.Resource}
 */
upvote.admin.lib.resources.buildResource = (url, opt_actions) => {
  /** @type {!Object<string,angular.ResourceAction>} */
  let actions = opt_actions || {};

  /**
   * @param {!angular.$resource} $resource
   * @return {!angular.Resource}
   * @ngInject
   */
  const resourceFactory = ($resource) => $resource(url, {}, actions);

  return resourceFactory;
};
const buildResource = upvote.admin.lib.resources.buildResource;


/**
 * @param {string} url
 * @param {?Object<string,angular.ResourceAction>=} opt_customActions
 * @return {function(!angular.$resource):!angular.Resource}
 */
upvote.admin.lib.resources.buildQueryResource = (url, opt_customActions) => {
  let defaultActions = {
    'search': {
      'method': 'GET',
      'params': {
        'platform': '@platform',
        'type': '@type',
        'cursor': '@cursor',
        'perPage': '@perPage',
        'asAdmin': '@asAdmin',
        'search': '@search',
        'searchBase': '@searchBase'
      }
    }
  };

  let actions = Object.assign({}, defaultActions, opt_customActions);

  return buildResource(url, actions);
};
});  // goog.scope
