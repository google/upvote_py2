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

goog.provide('upvote.exemptions.ExemptionDuration');
goog.provide('upvote.exemptions.ExemptionReason');
goog.provide('upvote.exemptions.ExemptionRequestData');
goog.provide('upvote.exemptions.ExemptionService');

goog.require('upvote.app.constants');

goog.scope(() => {


/**
 * Representations of the valid reasons for requesting a lockdown exemption.
 * These should mirror those in shared.constants.EXEMPTION_REASON.
 * @enum {string}
 * @export
 */
upvote.exemptions.ExemptionReason = {
  'DEVELOPER_MACOS': 'DEVELOPER_MACOS',
  'DEVELOPER_IOS': 'DEVELOPER_IOS',
  'DEVELOPER_DEVTOOLS': 'DEVELOPER_DEVTOOLS',
  'DEVELOPER_PERSONAL': 'DEVELOPER_PERSONAL',
  'USES_PACKAGE_MANAGER': 'USES_PACKAGE_MANAGER',
  'FEARS_NEGATIVE_IMPACT': 'FEARS_NEGATIVE_IMPACT',
  'OTHER': 'OTHER'
};


/**
 * Representations of the valid lockdown exemption durations.
 * These should mirror those in shared.constants.EXEMPTION_DURATION.
 * @enum {string}
 * @export
 */
upvote.exemptions.ExemptionDuration = {
  'DAY': 'DAY',
  'WEEK': 'WEEK',
  'MONTH': 'MONTH',
  'YEAR': 'YEAR'
};


/**
 * @typedef {{
 *   reason: !upvote.exemptions.ExemptionReason,
 *   otherText: ?string,
 *   duration: !upvote.exemptions.ExemptionDuration,
 * }}
 * @export
 */
upvote.exemptions.ExemptionRequestData;


upvote.exemptions.ExemptionService = class {

  /**
   * @param {!angular.$http} $http
   * @ngInject
   */
  constructor($http) {
    /** @private {!angular.$http} */
    this.http_ = $http;
  }

  /**
   * If present, return the exemption for the given host.
   * @param {string} hostId
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  getExemption(hostId) {
    const url = ExemptionService.BASE_URL_ + '/' + hostId;
    return this.http_.get(url);
  }

  /**
   * Requests an exemption for the given host.
   * @param {string} hostId
   * @param {!upvote.exemptions.ExemptionRequestData} requestData
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  requestExemption(hostId, requestData) {
    let url = ExemptionService.BASE_URL_ + '/' + hostId + '/request';
    return this.http_.post(url, requestData);
  }

  /**
   * Voluntarily cancels an exemption for the given host.
   * @param {string} hostId
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  cancelExemption(hostId) {
    let url = ExemptionService.BASE_URL_ + '/' + hostId + '/cancel';
    return this.http_.post(url, {});
  }

};
const ExemptionService = upvote.exemptions.ExemptionService;

/** @private {string} */
ExemptionService.BASE_URL_ = upvote.app.constants.WEB_PREFIX + 'exemptions';
});  // goog.scope
