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

goog.provide('upvote.admin.common.displayArray');
goog.provide('upvote.admin.common.timeSince');


/**
 * Return a string representation of an array.
 *
 * @param {?Array<Object>} inputArray
 * @return {string|?Array<Object>}
 */
upvote.admin.common.displayArray = (inputArray) => {
  if (Array.isArray(inputArray)) {
    return inputArray.join(', ');
  } else {
    return inputArray;
  }
};


/**
 * Return the time since the given date as a string.
 *
 * @param {string} dateString
 * @return {string}
 */
upvote.admin.common.timeSince = (dateString) => {
  let chunks = [
    {'seconds': 60 * 60 * 24 * 365, 'text': 'year'},
    {'seconds': 60 * 60 * 24 * 30, 'text': 'month'},
    {'seconds': 60 * 60 * 24 * 7, 'text': 'week'},
    {'seconds': 60 * 60 * 24, 'text': 'day'},
    {'seconds': 60 * 60, 'text': 'hour'},
    {'seconds': 60, 'text': 'minute'},
  ];

  const date = new Date(dateString);

  if (goog.isDateLike(date) && !isNaN(date.getTime())) {
    // Function to output the count and given text with an optional s
    let pluralize = (count, text) => {
      if (count > 1) return count + ' ' + text + 's';
      return count + ' ' + text;
    };

    // Get difference between input and now
    let delta = Date.now() - date.getTime();
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
    let result;

    // Find first positive result in |chunks|
    for (let i = 0; i < chunks.length; ++i) {
      const chunk = chunks[i];
      const count = Math.floor(delta / chunk['seconds']);
      if (count > 0) {
        result = pluralize(count, chunk['text']);

        if ((i + 1) < chunks.length) {
          const chunk2 = chunks[i + 1];
          const count2 = Math.floor(
              (delta - (chunk['seconds'] * count)) / chunk2['seconds']);
          if (count2 > 0) {
            result += ', ' + pluralize(count2, chunk2.text);
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
