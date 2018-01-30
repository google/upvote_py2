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

goog.provide('upvote.app.MainController');

goog.require('upvote.shared.Page');


/** Main controller for UI. */
upvote.app.MainController = class {
  /**
   * @param {!angular.Resource} settingResource
   * @param {!md.$mdMedia} $mdMedia
   * @param {!angular.Scope} $scope
   * @param {!upvote.shared.Page} page Details about the active page
   * @ngInject
   */
  constructor(settingResource, $mdMedia, $scope, page) {
    /** @private {!angular.Resource} */
    this.settingResource_ = settingResource;
    /** @private {!md.$mdMedia} */
    this.mdMedia_ = $mdMedia;
    /** @private {!angular.Scope} */
    this.scope_ = $scope;

    /** @export {?{siteName: string}} */
    this.appTitle = null;

    /** @export {boolean} */
    this.isSidenavOpen = false;

    /** @export {!upvote.shared.Page} */
    this.page = page;

    this.init_();
  }

  /** @private */
  init_() {
    this.appTitle = this.settingResource_.get({'setting': 'siteName'});

    this.isSidenavOpen = this.mdMedia_('gt-md');
    // Force-open the sidenav when the screen is greater than 'md'.
    this.scope_.$watch(
        () => {
          return this.mdMedia_('gt-md');
        },
        (isLgScreen) => {
          if (isLgScreen) {
            this.isSidenavOpen = true;
          }
        });
    // Force-close the sidenav when the screen is less than or equal to 'sm'.
    this.scope_.$watch(
        () => {
          return this.mdMedia_('(max-width: 959px)');
        },
        (isSmScreen) => {
          if (isSmScreen) {
            this.isSidenavOpen = false;
          }
        });
  }

};
