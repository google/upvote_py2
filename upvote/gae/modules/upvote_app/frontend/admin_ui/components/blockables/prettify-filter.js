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

goog.provide('upvote.admin.blockables.prettifyState');
goog.provide('upvote.admin.blockables.prettifyType');
goog.provide('upvote.admin.blockables.prettifyVotingProhibitedReason');

goog.require('goog.array');


/**
 * Return a sentence describing the given blockable state.
 *
 * @param {string} inputString
 * @return {string}
 */
upvote.admin.blockables.prettifyState = (inputString) => {
  switch (inputString) {
    case 'UNTRUSTED':
      return 'Untrusted';
    case 'APPROVED_FOR_LOCAL_WHITELISTING':
      return 'Can be whitelisted, if requested.';
    case 'LIMITED':
      return 'Allowed for a limited number of hosts.';
    case 'GLOBALLY_WHITELISTED':
      return 'Allowed everywhere.';
    case 'SILENT_BANNED':
      return 'Banned without notification for security reasons.';
    case 'BANNED':
      return 'Banned as malware or for security reasons.';
    default:
      return inputString;
  }
};


/**
 * Return a sentence describing the reason voting is prohibited on a blockable.
 *
 * @param {string} inputString
 * @return {string}
 */
upvote.admin.blockables.prettifyVotingProhibitedReason = (inputString) => {
  switch (inputString) {
    case 'PENDING':
      return 'This application has been whitelisted and is being processed.';
    case 'LIMITED':
      return 'This application is only approved for a limited number of machines.';
    case 'BANNED':
    case 'SILENT_BANNED':
      return 'This application is banned.';
    case 'GLOBALLY_WHITELISTED':
      return 'This application has been approved for use everywhere.';
    case 'ADMIN_ONLY':
      return 'Voting is currently only open to administrators.';
    case 'INSUFFICIENT_PERMISSION':
      return 'You do not have permission to vote on this application.';
    case 'BLACKLISTED_CERT':
      return 'The signing certificate for this application is blacklisted.';
    case 'UPLOADING_BUNDLE':
      return 'The application metadata is not yet fully uploaded.';
    case 'FLAGGED_BINARY':
      return 'This application contains a binary that\'s under review.';
    case 'FLAGGED_CERT':
      return 'This application is signed by a certificate that has been banned for security reasons.';
    default:
      return inputString;
  }
};


/**
 * Return the blockable type of the blockable represented by a property list.
 *
 * @param {Array<Object>} inputArray
 * @return {Array<Object>|string}
 */
upvote.admin.blockables.prettifyType = (inputArray) => {
  if (!angular.isArray(inputArray)) {
    return inputArray;
  } else if (goog.array.contains(inputArray, 'SantaBlockable')) {
    return 'Santa Blockable';
  } else if (goog.array.contains(inputArray, 'SantaCertificate')) {
    return 'Santa Certificate';
  } else if (goog.array.contains(inputArray, 'SantaBundle')) {
    return 'Santa Bundle';
  } else if (goog.array.contains(inputArray, 'Bit9Binary')) {
    return 'Bit9 Blockable';
  } else if (goog.array.contains(inputArray, 'Bit9Certificate')) {
    return 'Bit9 Certificate';
  } else {
    return 'Unknown';
  }
};
