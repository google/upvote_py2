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

goog.provide('upvote.admin.rulepage.RuleController');

goog.require('upvote.admin.lib.controllers.ModelController');
goog.require('upvote.shared.Page');

goog.scope(() => {
const ModelController = upvote.admin.lib.controllers.ModelController;


/** Rule model controller. */
upvote.admin.rulepage.RuleController = class extends ModelController {
  /**
   * @param {!angular.Resource} ruleResource
   * @param {!angular.Resource} ruleQueryResource
   * @param {!angular.$routeParams} $routeParams
   * @param {!angular.Scope} $scope
   * @param {!angular.$location} $location
   * @param {!upvote.shared.Page} page Details about the active webpage
   * @ngInject
   */
  constructor(
      ruleResource, ruleQueryResource, $routeParams, $scope, $location, page) {
    super(ruleResource, ruleQueryResource, $routeParams, $scope, $location);

    // No Bit9-specific Rule model implemented so no Bit9 option should be shown
    delete this.platforms['bit9'];

    /** @export {!Object<string, !upvote.admin.lib.controllers.Field>} */
    this.fields = RuleController.BASE_FIELDS_;

    page.title = 'Rules';

    // Initialize the controller
    this.init();
  }

  /** @override */
  updateToAll() {
    this.fields = RuleController.BASE_FIELDS_;
  }

  /** @override */
  updateToSanta() {
    this.fields = Object.assign({}, RuleController.BASE_FIELDS_, {
      'primary_user': {'displayName': 'Primary User', 'value': 'primary_user'},
      'serial_num': {'displayName': 'Serial Number', 'value': 'serial_num'},
      'santa_version':
          {'displayName': 'Santa Version', 'value': 'santa_version'}
    });
  }
};
let RuleController = upvote.admin.rulepage.RuleController;

/** @private @const {!Object<string, !upvote.admin.lib.controllers.Field>} */
RuleController.BASE_FIELDS_ = {
  'id': {'displayName': 'ID', 'value': 'id'},
  'hostname': {'displayName': 'Hostname', 'value': 'hostname'}
};
});  // goog.scope
