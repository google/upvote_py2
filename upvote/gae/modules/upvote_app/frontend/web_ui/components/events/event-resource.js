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

goog.provide('upvote.events.AnyEventWithContext');
goog.provide('upvote.events.EventQueryResource');
goog.provide('upvote.events.RecentEventResource');

goog.require('upvote.app.constants');
goog.require('upvote.lib.resources.buildResource');

goog.scope(() => {
let buildResource = upvote.lib.resources.buildResource;


/**
 * @typedef {{
 *   event: !upvote.shared.models.AnyEvent,
 *   host: !upvote.shared.models.AnyHost,
 *   blockable: !upvote.shared.models.AnyBlockable,
 *   cert: !upvote.shared.models.AnyBlockable,
 *   vote: !upvote.shared.models.Vote
 * }}
 */
upvote.events.AnyEventWithContext;


/** @export {function(angular.$resource):!angular.Resource} */
upvote.events.EventQueryResource =
    buildResource(upvote.app.constants.WEB_PREFIX + 'events/query', {
      'getPage': {
        'method': 'GET',
        'params': {
          'id': null,
          'cursor': '@cursor',
          'perPage': '@perPage',
          'asAdmin': '@asAdmin',
        }
      }
    });


upvote.events.RecentEventResource =
    buildResource(upvote.app.constants.WEB_PREFIX + 'events/most-recent/:id', {
      'get': {
        'method': 'GET',
        'params': {'id': null, 'withContext': '@withContext'}
      }
    });
});  // goog.scope
