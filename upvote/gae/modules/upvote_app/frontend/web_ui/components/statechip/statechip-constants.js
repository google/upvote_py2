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

goog.provide('upvote.statechip.State');
goog.provide('upvote.statechip.StateClassMap');
goog.provide('upvote.statechip.StateDisplayMap');

goog.require('upvote.shared.constants.UiBlockableState');

goog.scope(() => {

const UiState = upvote.shared.constants.UiBlockableState;


/**
 * A mapping of chip states to their user-facing strings.
 * @export {Object<upvote.shared.constants.UiBlockableState, string>}
 */
upvote.statechip.StateDisplayMap = {};
let StateDisplayMap = upvote.statechip.StateDisplayMap;
StateDisplayMap[UiState['AWAITING_VOTES']] = 'Awaiting Votes';
StateDisplayMap[UiState['AVAILABLE']] = 'Available';
StateDisplayMap[UiState['WHITELISTED']] = 'Whitelisted';
StateDisplayMap[UiState['GLOBALLY_WHITELISTED']] = 'Globally Whitelisted';
StateDisplayMap[UiState['FLAGGED']] = 'Flagged';
StateDisplayMap[UiState['BANNED']] = 'Banned';
StateDisplayMap[UiState['CERT_BANNED']] = 'Banned Publisher';
StateDisplayMap[UiState['CERT_WHITELISTED']] = 'Whitelisted Publisher';


/**
 * A mapping of chip states to their CSS class names.
 * @export {Object<upvote.shared.constants.UiBlockableState, string>}
 */
upvote.statechip.StateClassMap = {};
let StateClassMap = upvote.statechip.StateClassMap;
StateClassMap[UiState['AWAITING_VOTES']] = 'awaiting-votes';
StateClassMap[UiState['AVAILABLE']] = 'available';
StateClassMap[UiState['WHITELISTED']] = 'whitelisted';
StateClassMap[UiState['GLOBALLY_WHITELISTED']] = 'whitelisted';
StateClassMap[UiState['FLAGGED']] = 'flagged';
StateClassMap[UiState['BANNED']] = 'banned';
StateClassMap[UiState['CERT_BANNED']] = 'banned';
StateClassMap[UiState['CERT_WHITELISTED']] = 'whitelisted';
});  // goog.scope
