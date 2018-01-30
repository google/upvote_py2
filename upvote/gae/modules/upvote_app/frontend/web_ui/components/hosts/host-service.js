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
goog.provide('upvote.hosts.EventRateResponse');
goog.provide('upvote.hosts.ExceptionReason');
goog.provide('upvote.hosts.ExceptionRequestData');
goog.provide('upvote.hosts.HostService');
goog.provide('upvote.hosts.Platform');
goog.provide('upvote.hosts.PolicyLevel');
goog.provide('upvote.hosts.SearchParams');

goog.require('upvote.app.constants');

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
 * @typedef {{
 *   platform: !upvote.hosts.Platform,
 *   cursor: string,
 *   perPage: number,
 *   search: string,
 *   searchBase: string
 * }}
 */
upvote.hosts.SearchParams;


/**
 * Representations of the valid reasons for requesting a host exception.
 * These should mirror those in shared.constants.HOST_EXEMPTION_REASON
 * @enum {string}
 * @export
 */
upvote.hosts.ExceptionReason = {
  'OSX_DEVELOPER': 'OSX_DEVELOPER',
  'IOS_DEVELOPER': 'IOS_DEVELOPER',
  'DEVTOOLS_DEVELOPER': 'DEVTOOLS_DEVELOPER',
  'DEVELOPER_PERSONAL': 'DEVELOPER_PERSONAL',
  'PACKAGE_MANAGER': 'PACKAGE_MANAGER',
  'IM_A_BABY': 'IM_A_BABY',
  'OTHER': 'OTHER'
};


/**
 * @typedef {{
 *   reason: !upvote.hosts.ExceptionReason,
 *   otherText: ?string,
 * }}
 * @export
 */
upvote.hosts.ExceptionRequestData;


/**
 * @typedef {{
 *   avgRate: number,
 *   atMax: boolean,
 * }}
 * @export
 */
upvote.hosts.EventRateResponse;


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
   * If present, return the host exception request for the given user and host.
   * @param {!string} hostId
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  getExistingHostException(hostId) {
    let url =
        HostService.BASE_URL_ + '/' + hostId + HostService.EXCEPTION_SUFFIX_;
    return this.http_.get(url);
  }

  /**
   * Create a host exception request the given host.
   * @param {!string} hostId
   * @param {!upvote.hosts.ExceptionRequestData} requestData
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  requestHostException(hostId, requestData) {
    let url =
        HostService.BASE_URL_ + '/' + hostId + HostService.EXCEPTION_SUFFIX_;
    return this.http_.post(url, requestData);
  }

  /**
   * Request that the given host be put into lockdown mode.
   * @param {!string} hostId
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  requestLockdown(hostId) {
    let url =
        HostService.BASE_URL_ + '/' + hostId + HostService.LOCKDOWN_SUFFIX_;
    return this.http_.post(url, {});
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
   * Retrieve the average event rate for the given hosts.
   * @param {!string} hostId
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  getEventRate(hostId) {
    let url = HostService.BASE_URL_ + '/' + hostId + HostService.RATE_SUFFIX_;
    return this.http_.get(url);
  }

  /**
   * Sets the hidden state of a host
   * @param {!string} hostId
   * @param {!boolean} hidden hides if set to true, otherwise shows host
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  hide(hostId, hidden) {
    let url = HostService.BASE_URL_ + '/' + hostId +
        HostService.HIDDEN_SUFFIX_ + (hidden ? 'true' : 'false');
    return this.http_.put(url, {});
  }
};
let HostService = upvote.hosts.HostService;

/** @private {string} */
HostService.BASE_URL_ = upvote.app.constants.WEB_PREFIX + 'hosts';
/** @private {string} */
HostService.RATE_SUFFIX_ = '/event-rate';
/** @private {string} */
HostService.EXCEPTION_SUFFIX_ = '/request-exception';
/** @private {string} */
HostService.LOCKDOWN_SUFFIX_ = '/request-lockdown';
/** @private {string} */
HostService.HIDDEN_SUFFIX_ = '/hidden/';
/** @private {string} */
HostService.ASSOCIATED_URL_ = HostService.BASE_URL_ + '/associated';
/** @private {string} */
HostService.QUERY_URL_ = HostService.BASE_URL_ + '/query';
});  // goog.scope
