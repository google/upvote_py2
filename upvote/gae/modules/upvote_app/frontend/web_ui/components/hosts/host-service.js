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

goog.provide('upvote.hosts.ClientMode');
goog.provide('upvote.hosts.HostService');
goog.provide('upvote.hosts.Platform');
goog.provide('upvote.hosts.PolicyLevel');
goog.provide('upvote.hosts.ProtectionLevel');
goog.provide('upvote.hosts.SearchParams');

goog.require('upvote.app.constants');
goog.require('upvote.shared.constants.ExemptionState');

goog.scope(() => {

/**
 * @enum {string}
 * @export
 */
upvote.hosts.Platform = {
  'ALL': '',
  'SANTA': 'santa'
};


/**
 * @enum {string}
 * @export
 */
upvote.hosts.ClientMode = {
  'MONITOR': 'MONITOR',
  'LOCKDOWN': 'LOCKDOWN'
};


/**
 * @enum {string}
 * @export
 */
upvote.hosts.PolicyLevel = {
  'LOCKDOWN': 'LOCKDOWN',
  'BLOCK_AND_ASK': 'BLOCK_AND_ASK',
  'MONITOR': 'MONITOR',
  'DISABLED': 'DISABLED',
};


/**
 * The protection levels a host can have.
 * @enum {string}
 * @export
 */
upvote.hosts.ProtectionLevel = {
  'FULL': 'FULL',        // Lockdown enabled, transitive whitelisting disabled.
  'DEVMODE': 'DEVMODE',  // Lockdown enabled, transitive whitelisting enabled.
  'MINIMAL': 'MINIMAL',  // Lockdown disabled, transitive whitelisting disabled.
  'UNKNOWN': 'UNKNOWN',  // Cannot be determined.
};


/**
 * @typedef {{
 *   platform: !upvote.hosts.Platform,
 *   cursor: string,
 *   perPage: number,
 *   search: string,
 *   searchBase: string
 * }}
 */
upvote.hosts.SearchParams;


upvote.hosts.HostService = class {
  /**
   * @param {!angular.$http} $http
   * @ngInject
   */
  constructor($http) {
    /** @private {!angular.$http} */
    this.http_ = $http;
  }

  /**
   * Gets a Host by its ID.
   * @param {!string} hostId
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  get(hostId) {
    let url = HostService.BASE_URL_ + '/' + hostId;
    return this.http_.get(url);
  }

  /**
   * Searches for Hosts by platform and/or field value.
   * @param {!upvote.hosts.SearchParams} params
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  search(params) {
    let url = HostService.QUERY_URL_;

    if (params['platform']) {
      url += '/' + params['platform'];
    }
    let queryParams = Object.assign({}, params, {'platform': null});
    return this.http_.get(url, {'params': queryParams});
  }

  /**
   * Retrieve the list of hosts associated with the given (or current) user.
   * @param {!string=} opt_userId
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  getAssociatedHosts(opt_userId) {
    let url = HostService.ASSOCIATED_URL_;
    if (opt_userId) {
      url += '/' + opt_userId;
    }
    return this.http_.get(url);
  }

  /**
   * Sets the hidden state of a host
   * @param {string} hostId
   * @param {boolean} hide hides if set to true, otherwise shows host
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  setHidden(hostId, hide) {
    let url = HostService.BASE_URL_ + '/' + hostId +
        HostService.HIDDEN_SUFFIX_ + (hide ? 'true' : 'false');
    return this.http_.put(url, {});
  }

  /**
   * Sets the transitive whitelisting state of a host
   * @param {string} hostId
   * @param {boolean} enable enables transitive whitelisting if set to true,
   *     otherwise disables it.
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  setTransitive(hostId, enable) {
    let url = HostService.BASE_URL_ + '/' + hostId +
        HostService.TRANSITIVE_SUFFIX_ + (enable ? 'true' : 'false');
    return this.http_.put(url, {});
  }

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

  /**
   * Return whether a host has an APPROVED Exemption.
   * @param {!upvote.shared.models.AnyHost} host
   * @return {boolean}
   * @export
   */
  hasApprovedExemption(host) {
    if (host && host.exemption && host.exemption.state) {
      return host.exemption.state ==
          upvote.shared.constants.ExemptionState.APPROVED;
    }
    return false;
  }

  /**
   * Return whether a host has transitive whitelisting enabled.
   * @param {!upvote.shared.models.AnyHost} host
   * @return {boolean}
   * @export
   */
  isTransitiveWhitelistingEnabled(host) {
    if (this.isSantaHost(host)) {
      return host['transitiveWhitelistingEnabled'];
    } else {
      return false;
    }
  }

  /**
   * Return the protection level of a host.
   * @param {!upvote.shared.models.AnyHost} host
   * @return {!upvote.hosts.ProtectionLevel}
   * @export
   */
  getProtectionLevel(host) {
    if (this.hasApprovedExemption(host)) {
      return upvote.hosts.ProtectionLevel.MINIMAL;
    } else if (this.isTransitiveWhitelistingEnabled(host)) {
      return upvote.hosts.ProtectionLevel.DEVMODE;
    } else if (host) {
      return upvote.hosts.ProtectionLevel.FULL;
    } else {
      return upvote.hosts.ProtectionLevel.UNKNOWN;
    }
  }
};

let HostService = upvote.hosts.HostService;

/** @private {string} */
HostService.BASE_URL_ = upvote.app.constants.WEB_PREFIX + 'hosts';
/** @private {string} */
HostService.HIDDEN_SUFFIX_ = '/hidden/';
/** @private {string} */
HostService.TRANSITIVE_SUFFIX_ = '/transitive/';
/** @private {string} */
HostService.ASSOCIATED_URL_ = HostService.BASE_URL_ + '/associated';
/** @private {string} */
HostService.QUERY_URL_ = HostService.BASE_URL_ + '/query';
});  // goog.scope
