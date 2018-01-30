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

goog.provide('upvote.hostblockablespage.HostBlockableListController');

goog.require('upvote.listpage.BlockableListController');
goog.require('upvote.shared.Page');


upvote.hostblockablespage.HostBlockableListController =
    class extends upvote.listpage.BlockableListController {
  /**
   * @param {!angular.Resource} eventQueryResource
   * @param {!upvote.blockables.BlockableService} blockableService
   * @param {!upvote.hosts.HostService} hostService
   * @param {!upvote.errornotifier.ErrorService} errorService
   * @param {!angular.$location} $location
   * @param {!angular.$q} $q
   * @param {!angular.$routeParams} $routeParams
   * @param {!upvote.shared.Page} page Details about the active webpage
   * @ngInject
   */
  constructor(
      eventQueryResource, blockableService, hostService, errorService,
      $location, $q, $routeParams, page) {
    super(
        eventQueryResource, blockableService, errorService, $location, $q,
        page);

    /** @private {!upvote.hosts.HostService} */
    this.hostService_ = hostService;
    /** @private {!angular.$routeParams} */
    this.routeParams_ = $routeParams;

    /** @export {?string} */
    this.hostId = null;
    /** @export {?upvote.shared.models.AnyHost} */
    this.host = null;

    this.childInit_();
  }

  /** @protected */
  init() {}

  /** @private */
  childInit_() {
    this.hostId = this.routeParams_['hostId'] || null;
    if (this.hostId) {
      this.hostService_.get(this.hostId)
          .then((response) => {
            this.host = response['data'];
            this.page.title = 'Applications blocked on ' + this.host.hostname;
          })
          .catch((response) => {
            this.errorService.createDialogFromError(response);
          });
    } else {
      this.errorService.createSimpleToast('No host ID specified.');
    }

    // Load an initial page of results.
    this.loadMore();
  }

  /**
   * Return query params to add to the event query.
   * @return {!Object} An object of query params to add to the event query.
   * @protected
   */
  getQueryFilters() {
    return {'hostId': this.hostId};
  }
};
