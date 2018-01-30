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

goog.provide('upvote.admin.eventpage.EventController');

goog.require('upvote.admin.lib.controllers.ModelController');
goog.require('upvote.shared.Page');

goog.scope(() => {
const ModelController = upvote.admin.lib.controllers.ModelController;


/** Event model controller. */
upvote.admin.eventpage.EventController = class extends ModelController {
  /**
   * @param {!angular.Resource} eventResource
   * @param {!angular.Resource} eventQueryResource
   * @param {!angular.$routeParams} $routeParams
   * @param {!angular.Scope} $scope
   * @param {!angular.$location} $location
   * @param {!upvote.shared.Page} page Details about the active webpage
   * @ngInject
   */
  constructor(
      eventResource, eventQueryResource, $routeParams, $scope, $location,
      page) {
    super(eventResource, eventQueryResource, $routeParams, $scope, $location);

    /** @export {string} */
    this.hostId = this.location.search()['hostId'];
    /** @export {string} */
    this.pageTitle = this.hostId ? 'Events for Host ' + this.hostId : 'Events';

    // Add the hostId param to the request before loadData is called by init.
    this.requestData['hostId'] = this.hostId;

    page.title = this.pageTitle;

    // Initialize the controller.
    this.init();
  }

  /**
   * Navigate to the Blockable page associated with the selected Event.
   * @export
   */
  goToBlockable() {
    this.location.path('/admin/blockables/' + this.card.blockableId).search({});
  }

  /**
   * Navigate to the Host page associated with the selected Event.
   * @export
   */
  goToHost() {
    this.location.path('/admin/hosts/' + this.card.hostId).search({});
  }
};
});  // goog.scope
