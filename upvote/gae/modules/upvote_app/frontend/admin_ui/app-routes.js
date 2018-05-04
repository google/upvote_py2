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
goog.provide('upvote.admin.app.routeProvider');

goog.require('upvote.admin.app.constants');


/**
 * Sets up Angular routes.
 *
 * @param {!angular.$routeProvider} $routeProvider
 * @param {!angular.$locationProvider} $locationProvider
 * @ngInject
 */
upvote.admin.app.routeProvider = ($routeProvider, $locationProvider) => {
  $locationProvider.html5Mode(true);

  $routeProvider
      .when(upvote.admin.app.constants.URL_PREFIX, {
        templateUrl: upvote.admin.app.constants.STATIC_URL_PREFIX +
            'dashboard/dashboard.html',
        controller: 'DashboardController',
        controllerAs: 'dashboardCtrl'
      })
      .when(upvote.admin.app.constants.URL_PREFIX + 'dashboard', {
        templateUrl: upvote.admin.app.constants.STATIC_URL_PREFIX +
            'dashboard/dashboard.html',
        controller: 'DashboardController',
        controllerAs: 'dashboardCtrl'
      })
      .when(upvote.admin.app.constants.URL_PREFIX + 'blockables/:id?', {
        templateUrl: upvote.admin.app.constants.STATIC_URL_PREFIX +
            'blockablepage/blockables.html',
        controller: 'BlockableController',
        controllerAs: 'blockableCtrl'
      })
      .when(upvote.admin.app.constants.URL_PREFIX + 'emergency', {
        templateUrl: upvote.admin.app.constants.STATIC_URL_PREFIX +
            'emergencypage/emergency.html',
        controller: 'EmergencyController',
        controllerAs: 'emergencyCtrl'
      })
      .when(upvote.admin.app.constants.URL_PREFIX + 'events/:id?', {
        templateUrl: upvote.admin.app.constants.STATIC_URL_PREFIX +
            'eventpage/events.html',
        controller: 'EventController',
        controllerAs: 'eventCtrl'
      })
      .when(upvote.admin.app.constants.URL_PREFIX + 'hosts/:id?', {
        templateUrl: upvote.admin.app.constants.STATIC_URL_PREFIX +
            'hostpage/hosts.html',
        controller: 'HostController',
        controllerAs: 'hostCtrl'
      })
      .when(upvote.admin.app.constants.URL_PREFIX + 'rules/:id?', {
        templateUrl: upvote.admin.app.constants.STATIC_URL_PREFIX +
            'rulepage/rules.html',
        controller: 'RuleController',
        controllerAs: 'ruleCtrl'
      })
      .when(upvote.admin.app.constants.URL_PREFIX + 'settings', {
        templateUrl: upvote.admin.app.constants.STATIC_URL_PREFIX +
            'settingspage/settings.html',
        controller: 'SettingsController',
        controllerAs: 'settingsCtrl'
      })
      .when(upvote.admin.app.constants.URL_PREFIX + 'users/:id?', {
        templateUrl: upvote.admin.app.constants.STATIC_URL_PREFIX +
            'userpage/users.html',
        controller: 'UserController',
        controllerAs: 'userCtrl'
      })
      .when(upvote.admin.app.constants.URL_PREFIX + 'votes/:id?', {
        templateUrl: upvote.admin.app.constants.STATIC_URL_PREFIX +
            'votepage/votes.html',
        controller: 'VoteController',
        controllerAs: 'voteCtrl'
      });
};
