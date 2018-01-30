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

goog.provide('upvote.admin.app.MainController');

goog.require('upvote.shared.Page');


/** Main controller for UI. */
upvote.admin.app.MainController = class {
  /**
   * @param {!angular.Resource} userResource
   * @param {!angular.Scope} $rootScope
   * @param {!upvote.shared.Page} page Details about the active page
   * @ngInject
   */
  constructor(userResource, $rootScope, page) {
    /** @private {!angular.Resource} */
    this.userResource_ = userResource;
    /** @private {!angular.Scope} */
    this.rootScope_ = $rootScope;

    /** @export {boolean} */
    this.isSidenavOpen = false;

    /** @export {!upvote.shared.Page} */
    this.page = page;

    this.init_();
  }

  /** @private */
  init_() {
    this.userResource_['getSelf']()['$promise'].then((user) => {
      this.rootScope_['currentUser'] = user;
    });
  }

};
