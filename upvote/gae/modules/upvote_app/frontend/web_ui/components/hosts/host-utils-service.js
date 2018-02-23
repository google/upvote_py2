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

goog.provide('upvote.hosts.HostUtilsService');

goog.require('upvote.app.constants');
goog.require('upvote.hosts.ClientMode');
goog.require('upvote.hosts.PolicyLevel');


goog.scope(() => {

upvote.hosts.HostUtilsService = class {
  /**
   * Return whether a host is a SantaHost.
   * @param {!upvote.shared.models.AnyHost} host
   * @return {boolean}
   * @export
   */
  isSantaHost(host) {
    return host && host['class_'].includes('SantaHost');
  }

  /**
   * Return whether a host is a Bit9Host.
   * @param {!upvote.shared.models.AnyHost} host
   * @return {boolean}
   * @export
   */
  isBit9Host(host) {
    return host && host['class_'].includes('Bit9Host');
  }

  /**
   * Returns the image URL associated with a host's platform.
   * @param {!upvote.shared.models.AnyHost} host
   * @return {string} The URL path of the image for the host's platform
   * @export
   */
  getPlatformImageURL(host) {
    switch (host['operatingSystemFamily']) {
      case upvote.app.constants.PLATFORMS.MACOS:
        return '/static/images/apple_logo.svg';
      case upvote.app.constants.PLATFORMS.WINDOWS:
        return '/static/images/windows_logo.svg';
      default:
        return '';
    }
  }


  /**
   * Return whether a host is in Lockdown mode.
   * @param {!upvote.shared.models.AnyHost} host
   * @return {boolean}
   * @export
   */
  isInLockdown(host) {
    if (this.isSantaHost(host)) {
      return host['clientMode'] == upvote.hosts.ClientMode['LOCKDOWN'];
    } else if (this.isBit9Host(host)) {
      return host['policyEnforcementLevel'] ==
          upvote.hosts.PolicyLevel['LOCKDOWN'];
    } else {
      return false;
    }
  }
};
let HostUtilsService = upvote.hosts.HostUtilsService;
});  // goog.scope
