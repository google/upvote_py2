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

goog.provide('upvote.admin.users.prettifyRole');


/**
 * Return a prettier representation of a user role.
 *
 * @param {string} inputString
 * @return {string}
 */
upvote.admin.users.prettifyRole = (inputString) => {
  const map = upvote.admin.users.prettifyRole.MAP_;
  if (map.hasOwnProperty(inputString)) {
    return map[inputString];
  } else {
    return inputString;
  }
};


/** @private @const {!Object<string, string>} */
upvote.admin.users.prettifyRole.MAP_ = {
  'USER': 'User',
  'TRUSTED_USER': 'Trusted User',
  'UNTRUSTED_USER': 'Untrusted User',
  'SUPERUSER': 'Superuser',
  'ADMINISTRATOR': 'Administrator',
  'VOTE': 'Administrator',
  'FLAG': 'Administrator',
  'AUTHORIZE': 'Administrator',
  'VIEW_SELF_EVENTS': 'View Own Events',
  'VIEW_SELF_HOSTS': 'View Own Hosts',
  'VIEW_OTHER_EVENTS': 'View All Events',
  'VIEW_HOST_IP': 'View Host IPs',
  'MARK_INSTALLER': 'Mark Blockable as Installer',
  'MARK_MALWARE': 'Mark Blockable as Malware',
  'UNFLAG': 'Unflag Blockable',
  'ADD_OVERRIDE': 'Add Policy Override',
  'CHANGE_BLOCKABLE_STATE': 'Change the State of a Blockable',
  'CHANGE_CERTIFICATE_STATE': 'Change the State of a Certificate'
};
