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

goog.provide('upvote.blockables.BlockableService');

goog.require('upvote.app.constants');

goog.scope(() => {


upvote.blockables.BlockableService = class {
  /**
   * @param {!angular.$http} $http
   * @ngInject
   */
  constructor($http) {
    /** @private {!angular.$http} */
    this.http_ = $http;
  }

  /**
   * Gets a Blockable by its ID.
   * @param {string} blockableId
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  get(blockableId) {
    let url = BlockableService.BASE_URL_ + '/' + blockableId;
    return this.http_.get(url);
  }

  /**
   * Retrieve the contents of a bundle.
   * @param {string} blockableId
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  getPackageContents(blockableId) {
    let url = BlockableService.BASE_URL_ + '/' + blockableId +
        BlockableService.CONTENTS_SUFFIX_;
    return this.http_.get(url);
  }

  /**
   * Retrieve whether the blockable has a pending state change.
   * @param {string} blockableId
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  getPending(blockableId) {
    let url = BlockableService.BASE_URL_ + '/' + blockableId +
        BlockableService.PENDING_SUFFIX_;
    return this.http_.get(url);
  }

  /**
   * Retrieve whether the blockable has a pending installer state change.
   * @param {string} blockableId
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  getInstallerPending(blockableId) {
    let url = BlockableService.BASE_URL_ + '/' + blockableId +
        BlockableService.INSTALLER_PENDING_SUFFIX_;
    return this.http_.get(url);
  }

  /**
   * Set whether a blockable is considered an installer.
   * @param {string} blockableId
   * @param {!boolean} force Whether the blockable should be marked as an
   *     installer.
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  setInstallerForce(blockableId, force) {
    let url = BlockableService.BASE_URL_ + '/' + blockableId +
        BlockableService.INSTALLER_SUFFIX_;
    return this.http_.post(url, {'value': force});
  }
};
let BlockableService = upvote.blockables.BlockableService;

/** @private {string} */
BlockableService.BASE_URL_ = upvote.app.constants.WEB_PREFIX + 'blockables';
/** @private {string} */
BlockableService.PENDING_SUFFIX_ = '/pending-state-change';
/** @private {string} */
BlockableService.INSTALLER_PENDING_SUFFIX_ = '/pending-installer-state-change';
/** @private {string} */
BlockableService.INSTALLER_SUFFIX_ = '/installer-state';
/** @private {string} */
BlockableService.CONTENTS_SUFFIX_ = '/contents';
});  // goog.scope
