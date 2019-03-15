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

goog.provide('upvote.features.FeatureService');

goog.require('upvote.app.constants');

goog.scope(() => {


upvote.features.FeatureService = class {
  /**
   * @param {!angular.$http} $http
   * @ngInject
   */
  constructor($http) {
    /** @const @private {!angular.$http} */
    this.http_ = $http;
  }

  /**
   * Determines if a given feature is available for use.
   * @param {string} feature
   * @return {!angular.$http.HttpPromise}
   * @export
   */
  available(feature) {
    const url = FeatureService.BASE_URL_ + '/' + feature;
    return this.http_.get(url);
  }
};
const FeatureService = upvote.features.FeatureService;

/** @const @private {string} */
FeatureService.BASE_URL_ = upvote.app.constants.WEB_PREFIX + 'features';
});  // goog.scope
