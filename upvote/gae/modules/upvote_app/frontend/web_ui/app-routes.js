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

/**
 * @fileoverview Route descriptions.
 */
goog.provide('upvote.app.routeProvider');

goog.require('upvote.app.constants');


/**
 * Sets up Angular routes.
 * @param {!angular.$routeProvider} $routeProvider
 * @param {!angular.$locationProvider} $locationProvider
 * @export
 * @ngInject
 */
upvote.app.routeProvider = ($routeProvider, $locationProvider) => {
  $locationProvider.html5Mode(true);

  let blockableListRoute = '/blockables';
  let blockableDetailsRoute = '/blockables/:id';
  $routeProvider
      .when(blockableListRoute, {
        templateUrl: upvote.app.constants.STATIC_URL_PREFIX +
            'listpage/blockable-list.html',
        controller: 'BlockableListController',
        controllerAs: 'blockableListCtrl',
      })
      .when('/', {redirectTo: blockableListRoute})
      .when(blockableDetailsRoute, {
        templateUrl: upvote.app.constants.STATIC_URL_PREFIX +
            'detailpage/blockable-details.html',
        controller: 'BlockableDetailsController',
        controllerAs: 'ctrl',
      })
      .when('/hosts', {
        templateUrl: upvote.app.constants.STATIC_URL_PREFIX +
            'hostlistpage/host-list.html',
        controller: 'HostListController',
        controllerAs: 'hostListCtrl',
      })
      .when('/hosts/:id/modify-protection', {
        templateUrl: upvote.app.constants.STATIC_URL_PREFIX +
            'modifyprotectionpage/modify-protection.html',
        controller: 'ModifyProtectionController',
        controllerAs: 'modifyProtectionCtrl',
      })
      .when('/hosts/:hostId/blockables', {
        templateUrl: upvote.app.constants.STATIC_URL_PREFIX +
            'listpage/blockable-list.html',
        controller: 'HostBlockableListController',
        controllerAs: 'blockableListCtrl',
      })
      .otherwise({redirectTo: blockableListRoute});
};
