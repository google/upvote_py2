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

goog.provide('upvote.common.blockableDisplayName');
goog.provide('upvote.common.blockableDisplayState');
goog.provide('upvote.common.blockableStateText');
goog.provide('upvote.common.displayArray');
goog.provide('upvote.common.hostDisplayHostname');
goog.provide('upvote.common.timeSince');
goog.provide('upvote.common.truncateHash');

goog.require('upvote.shared.models.AnyBlockable');
goog.require('upvote.shared.utils.isCertBlockable');
goog.require('upvote.shared.utils.isPackageBlockable');


/**
 * Return a string representation of an array.
 *
 * @param {?Array<Object>} inputArray
 * @return {string|?Array<Object>}
 */
upvote.common.displayArray = (inputArray) => {
  if (Array.isArray(inputArray)) {
    return inputArray.join(', ');
  } else {
    return inputArray;
  }
};


/**
 * Return a name to display for the given blockable.
 *
 * @param {?upvote.shared.models.AnyBlockable} blockable
 * @return {string}
 */
upvote.common.blockableDisplayName = (blockable) => {
  if (!blockable) {
    return '';
  } else if (upvote.shared.utils.isPackageBlockable(blockable)) {
    return blockable['name'] || blockable['bundleId'] || '';
  } else if (upvote.shared.utils.isCertBlockable(blockable)) {
    return blockable['organization'] || blockable['commonName'] || '';
  } else {
    return blockable['fileName'] || '';
  }
};


/**
 * Return a human-readable representation of a blockable's state.
 *
 * @param {string} state
 * @return {string}
 */
upvote.common.blockableStateText = (state) => {
  switch (state) {
    case 'UNTRUSTED':
      return 'Untrusted Binary';
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
      return state;
  }
};


/**
 * Return a short representation of a blockable's hostname.
 *
 * @param {string} hostname
 * @return {string}
 */
upvote.common.hostDisplayHostname = (hostname) => {
  if (goog.isString(hostname) && hostname.length) {
    return hostname.split('.')[0];
  } else {
    return hostname;
  }
};


/**
 * Return a short representation of a hash.
 *
 * @param {string} hash
 * @return {string}
 */
upvote.common.truncateHash = (hash) => {
  if (goog.isString(hash)) {
    return hash.slice(0, 8);
  } else {
    return hash;
  }
};


/**
 * Return the time since the given date as a string.
 *
 * @param {string} dateString
 * @return {string}
 */
upvote.common.timeSince = (dateString) => {
  var chunks = [
    {'seconds': 60 * 60 * 24 * 365, 'text': 'year'},
    {'seconds': 60 * 60 * 24 * 30, 'text': 'month'},
    {'seconds': 60 * 60 * 24 * 7, 'text': 'week'},
    {'seconds': 60 * 60 * 24, 'text': 'day'},
    {'seconds': 60 * 60, 'text': 'hour'}, {'seconds': 60, 'text': 'minute'}
  ];

  var date = new Date(dateString);

  if (goog.isDateLike(date) && !isNaN(date.getTime())) {
    // Function to output the count and given text with an optional s
    var pluralize = function(count, text) {
      if (count > 1) return count + ' ' + text + 's';
      return count + ' ' + text;
    };

    // Get difference between input and now
    var delta = Date.now() - date.getTime();
    delta = Math.floor(delta / 1000);  // Ignore milliseconds

    // Ensure time is in future
    if (delta <= 0) {
      return '0 minutes';
    }

    // Ensure time is over 1 minute ago
    if (delta < 60) {
      return pluralize(delta, 'second') + ' ago';
    }

    // Will be appended to ready to output
    var result;

    // Find first positive result in |chunks|
    for (var i = 0; i < chunks.length; ++i) {
      var chunk = chunks[i];
      var count = Math.floor(delta / chunk['seconds']);
      if (count > 0) {
        result = pluralize(count, chunk['text']);

        if ((i + 1) < chunks.length) {
          var chunk2 = chunks[i + 1];
          var count2 = Math.floor(
              (delta - (chunk['seconds'] * count)) / chunk2['seconds']);
          if (count2 > 0) {
            result += ', ' + pluralize(count2, chunk2['text']);
          }
          break;
        }
      }
    }

    return result + ' ago';
  } else {
    return dateString;
  }
};
