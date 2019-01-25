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

goog.provide('upvote.hosts.prettifyEnforcementLevel');
goog.provide('upvote.hosts.prettifyExemption');
goog.provide('upvote.hosts.prettifyMode');

goog.require('upvote.hosts.ClientMode');
goog.require('upvote.hosts.ExemptionState');
goog.require('upvote.hosts.PolicyLevel');


/**
 * Return a prettier representation of the host mode.
 * @param {?string} inputString
 * @return {?string}
 */
upvote.hosts.prettifyMode = function(inputString) {
  if (!angular.isString(inputString)) {
    return inputString;
  } else if (inputString == upvote.hosts.ClientMode.LOCKDOWN) {
    return 'Protected';
  } else if (inputString == upvote.hosts.ClientMode.MONITOR) {
    return 'Minimally Protected';
  } else {
    return 'Unknown';
  }
};


/**
 * Translate the Bit9 policy level to a host mode.
 * @param {?string} enforcementLevel
 * @return {?string}
 */
upvote.hosts.prettifyEnforcementLevel = (enforcementLevel) => {
  if (!angular.isString(enforcementLevel)) {
    return enforcementLevel;
  }
  switch (enforcementLevel) {
    case upvote.hosts.PolicyLevel.LOCKDOWN:
      return 'Protected';
    case upvote.hosts.PolicyLevel.BLOCK_AND_ASK:
      return 'Mostly Protected';
    case upvote.hosts.PolicyLevel.MONITOR:
      return 'Minimally Protected';
    case upvote.hosts.PolicyLevel.DISABLED:
      return 'Unprotected';
    default:
      return 'Unknown';
  }
};


/**
 * Converts a date string to something more user-friendly.
 * @param {string} dateStr Date string.
 * @return {string}
 */
upvote.hosts.prettifyDate = function(dateStr) {
  let dateObj = new Date(dateStr);

  let days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  let months = [
    'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov',
    'Dec'
  ];

  let day = days[dateObj.getDay()];
  let month = months[dateObj.getMonth() + 1];
  let date = dateObj.getDate();
  let year = dateObj.getFullYear();

  return `${day}, ${month} ${date}, ${year}`;
};


/**
 * Returns a user-friendly Exemption description.
 * @param {!upvote.shared.models.Exemption} exm Exemption to be converted.
 * @return {string} A user-friendly string.
 */
upvote.hosts.prettifyExemption = function(exm) {
  if (exm == null) {
    return '';
  }
  switch (exm.state) {
    case upvote.hosts.ExemptionState.REQUESTED:
      return 'Pending Approval';
    case upvote.hosts.ExemptionState.PENDING:
      return 'Pending Approval';
    case upvote.hosts.ExemptionState.APPROVED:
      return 'Approved until ' + upvote.hosts.prettifyDate(exm.deactivationDt);
    case upvote.hosts.ExemptionState.DENIED:
      return 'Denied';
    case upvote.hosts.ExemptionState.ESCALATED:
      return 'Escalated';
    case upvote.hosts.ExemptionState.EXPIRED:
      return 'Expired on ' + upvote.hosts.prettifyDate(exm.deactivationDt);
    case upvote.hosts.ExemptionState.REVOKED:
      return 'Revoked on ' + upvote.hosts.prettifyDate(exm.deactivationDt);
    default:
      return '';
  }
};
