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

goog.provide('upvote.statechip.StateToClass');
goog.provide('upvote.statechip.StateToDisplay');
goog.provide('upvote.statechip.ToUiState');

goog.require('upvote.shared.constants.BlockableState');
goog.require('upvote.shared.constants.UiBlockableState');
goog.require('upvote.statechip.StateClassMap');
goog.require('upvote.statechip.StateDisplayMap');

goog.scope(() => {

const BlockableState = upvote.shared.constants.BlockableState;
const UiState = upvote.shared.constants.UiBlockableState;

/**
 * Convert the Blockable's state to its corresponding statechip state.
 * @param {upvote.shared.constants.BlockableState} blockableState
 * @param {?upvote.shared.models.Vote} vote
 * @param {?upvote.shared.models.SantaCertificate} cert
 * @return {?upvote.shared.constants.UiBlockableState}
 */
upvote.statechip.ToUiState = function(blockableState, vote, cert) {
  // If the binary has blockable-specific rules associated with it, display the
  // binary's state at the highest priority.
  switch (blockableState) {
    case BlockableState['APPROVED_FOR_LOCAL_WHITELISTING']:
      if (!!vote && vote['wasYesVote']) {
        return UiState['WHITELISTED'];
      } else {
        return UiState['AVAILABLE'];
      }
    case BlockableState['LIMITED']:
    case BlockableState['GLOBALLY_WHITELISTED']:
      return UiState['GLOBALLY_WHITELISTED'];
    case BlockableState['SILENT_BANNED']:
    case BlockableState['BANNED']:
      return UiState['BANNED'];
  }
  // If the binary has no blockable-specific rules but does have cert-specific
  // rules, display the cert's state.
  if (!!cert) {
    let certState = cert['state'];
    switch (certState) {
      case BlockableState['GLOBALLY_WHITELISTED']:
        return UiState['CERT_WHITELISTED'];
      case BlockableState['BANNED']:
        return UiState['CERT_BANNED'];
    }
  }
  // If the binary has neither blockable-specific nor cert-specific rules,
  // display the binary's state.
  switch (blockableState) {
    case BlockableState['UNTRUSTED']:
      return UiState['AWAITING_VOTES'];
    case BlockableState['SUSPECT']:
      return UiState['FLAGGED'];
  }
  return null;
};


/**
 * Return a user-readable representation of a blockable's state.
 * @param {upvote.shared.constants.UiBlockableState} chipState
 * @return {string}
 */
upvote.statechip.StateToDisplay = function(chipState) {
  let state = upvote.statechip.StateDisplayMap[chipState];
  return state || chipState;
};


/**
 * Return the CSS class associated with a blockable's state.
 * @param {upvote.shared.constants.UiBlockableState} chipState
 * @return {string}
 */
upvote.statechip.StateToClass = function(chipState) {
  return upvote.statechip.StateClassMap[chipState];
};
});  // goog.scope
