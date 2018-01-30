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

goog.provide('upvote.admin.hosts.prettifyMode');
goog.provide('upvote.admin.hosts.prettifyUuid');


/**
 * Return a prettier representation of the host mode.
 *
 * @param {?string} inputString
 * @return {?string}
 */
upvote.admin.hosts.prettifyMode = (inputString) => {
  if (!angular.isString(inputString)) {
    return inputString;
  } else if (inputString == 'MONITOR') {
    return 'Monitor Mode';
  } else if (inputString == 'LOCKDOWN') {
    return 'Lockdown Mode';
  } else {
    return 'Unknown State';
  }
};


/**
 * Return a prettier representation of the host uuid.
 *
 * @param {?string} inputString
 * @return {?string}
 */
upvote.admin.hosts.prettifyUuid = (inputString) => {
  if (angular.isString(inputString)) {
    return inputString.slice(0, 7);
  } else {
    return inputString;
  }
};
