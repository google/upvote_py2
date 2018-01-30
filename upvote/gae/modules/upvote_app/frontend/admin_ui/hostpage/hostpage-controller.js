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

goog.provide('upvote.admin.hostpage.HostController');

goog.require('upvote.admin.lib.controllers.ModelController');
goog.require('upvote.errornotifier.ErrorService');
goog.require('upvote.hosts.HostService');
goog.require('upvote.shared.Page');

goog.scope(() => {
const ModelController = upvote.admin.lib.controllers.ModelController;


/** Host model controller. */
upvote.admin.hostpage.HostController = class extends ModelController {
  /**
   * @param {!angular.Resource} hostResource
   * @param {!angular.Resource} hostQueryResource
   * @param {!upvote.hosts.HostService} hostService
   * @param {!upvote.errornotifier.ErrorService} errorService
   * @param {!angular.$routeParams} $routeParams
   * @param {!angular.Scope} $scope
   * @param {!angular.Scope} $rootScope
   * @param {!angular.$location} $location
   * @param {!upvote.shared.Page} page Details about the active webpage
   * @ngInject
   */
  constructor(
      hostResource, hostQueryResource, hostService, errorService, $routeParams,
      $scope, $rootScope, $location, page) {
    super(hostResource, hostQueryResource, $routeParams, $scope, $location);

    // No Bit9-specific Host model implemented so no Bit9 option should be shown
    delete this.platforms['bit9'];

    /** @export {!Object<string, !upvote.admin.lib.controllers.Field>} */
    this.fields = HostController.BASE_FIELDS_;
    /** @private {!upvote.errornotifier.ErrorService} errorService */
    this.errorService_ = errorService;
    /** @private {!upvote.hosts.HostService} */
    this.hostService_ = hostService;
    /** @export {!angular.Scope} */
    this.rootScope = $rootScope;

    page.title = 'Hosts';

    // Initialize the controller
    this.init();
  }

  /** @override */
  updateToAll() {
    this.fields = HostController.BASE_FIELDS_;
  }

  /** @override */
  loadCard() {
    let cardPromise = super.loadCard();
    return (!cardPromise) ? cardPromise : cardPromise.then(() => {
      this.card['user'] = this.rootScope['currentUser'];
      delete this.card['user']['$promise'];
    });
  }

  /** @override */
  updateToSanta() {
    this.fields = Object.assign({}, HostController.BASE_FIELDS_, {
      'primary_user': {'displayName': 'Primary User', 'value': 'primary_user'},
      'serial_num': {'displayName': 'Serial Number', 'value': 'serial_num'},
      'santa_version':
          {'displayName': 'Santa Version', 'value': 'santa_version'}
    });
  }

  /**
   * Navigate to the Event page for the selected Host.
   * @export
   */
  goToHostEvents() {
    this.location.path('/admin/events').search({'hostId': this.card['id']});
  }
};
let HostController = upvote.admin.hostpage.HostController;

/** @private {!Object<string, !upvote.admin.lib.controllers.Field>} */
HostController.BASE_FIELDS_ = {
  'id': {'displayName': 'ID', 'value': 'id'},
  'hostname': {'displayName': 'Hostname', 'value': 'hostname'}
};
});  // goog.scope
