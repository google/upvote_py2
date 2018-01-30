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

goog.provide('upvote.admin.dashboard.DashboardController');

goog.require('upvote.admin.app.constants');
goog.require('upvote.errornotifier.ErrorService');
goog.require('upvote.shared.models.AnyBlockable');


/** Controller for the admin dashboard. */
upvote.admin.dashboard.DashboardController = class {
  /**
   * @param {!angular.Resource} blockableQueryResource
   * @param {!upvote.errornotifier.ErrorService} errorService
   * @param {!angular.$location} $location
   * @param {!Object} page
   * @ngInject
   */
  constructor(blockableQueryResource, errorService, $location, page) {
    /** @private {!angular.Resource} */
    this.blockableQueryResource_ = blockableQueryResource;
    /** @private {!upvote.errornotifier.ErrorService} */
    this.errorService_ = errorService;
    /** @private {!angular.$location} */
    this.location_ = $location;

    /** @export {!Array<upvote.shared.models.AnyBlockable>} */
    this.suspectBlockables = [];
    /** @export {!Array<upvote.shared.models.AnyBlockable>} */
    this.flaggedBlockables = [];

    page.title = 'Dashboard';

    this.init_();
  }

  /** @private */
  init_() {
    this.blockableQueryResource_['search'](
            {'filter': 'suspect', 'platform': 'all', 'type': 'all'})['$promise']
        .then((response) => {
          this.suspectBlockables = response['content'];
        })
        .catch((response) => {
          this.errorService_.createToastFromError(response);
        });
    this.blockableQueryResource_['search'](
            {'filter': 'flagged', 'platform': 'all', 'type': 'all'})['$promise']
        .then((response) => {
          this.flaggedBlockables = response['content'];
        })
        .catch((response) => {
          this.errorService_.createToastFromError(response);
        });
  }

  /**
   * Handles selecting an item.
   * @param {number} itemId The id of the selected item.
   * @export
   */
  onSelectedItem(itemId) {
    const newPath =
        upvote.admin.app.constants.URL_PREFIX + 'blockables/' + itemId;
    this.location_.path(newPath);
  }
};
