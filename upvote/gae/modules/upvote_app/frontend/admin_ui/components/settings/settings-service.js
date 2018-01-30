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

goog.provide('upvote.admin.settings.SettingsService');

goog.require('upvote.admin.app.constants');

goog.scope(() => {


upvote.admin.settings.SettingsService = class {
  /**
   * @param {!angular.$http} $http
   * @ngInject
   */
  constructor($http) {
    /** @private {!angular.$http} */
    this.http_ = $http;
  }

  /**
   * Gets a setting value by name.
   * @param {!string} settingName
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  get(settingName) {
    const url = SettingsService.BASE_URL_ + '/' + settingName;
    return this.http_.get(url);
  }

  /**
   * Sets the value of an API key.
   * @param {string} keyName
   * @param {string} value
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  setApiKey(keyName, value) {
    const url = SettingsService.API_KEY_URL_ + '/' + keyName;
    // JSON serialization necessary to allow deserialization into Python dicts
    // on the webapp2 side.
    return this.http_.post(url, {'value': value});
  }
};
let SettingsService = upvote.admin.settings.SettingsService;

/** @private {string} */
SettingsService.BASE_URL_ = upvote.admin.app.constants.WEB_PREFIX + 'settings';
SettingsService.API_KEY_URL_ = SettingsService.BASE_URL_ + '/api-keys';
});  // goog.scope
