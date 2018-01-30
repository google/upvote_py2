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

goog.provide('upvote.admin.userpage.UserController');

goog.require('upvote.admin.app.constants');
goog.require('upvote.admin.lib.controllers.ModelController');
goog.require('upvote.errornotifier.ErrorService');
goog.require('upvote.shared.Page');

goog.scope(() => {
const ModelController = upvote.admin.lib.controllers.ModelController;


/** User model controller. */
upvote.admin.userpage.UserController = class extends ModelController {
  /**
   * @param {!angular.Resource} userResource
   * @param {!angular.Resource} userQueryResource
   * @param {!angular.Resource} constantResource
   * @param {!upvote.errornotifier.ErrorService} errorService
   * @param {!angular.$routeParams} $routeParams
   * @param {!angular.Scope} $scope
   * @param {!angular.Scope} $rootScope
   * @param {!angular.$location} $location
   * @param {!upvote.shared.Page} page Details about the active webpage
   * @ngInject
   */
  constructor(
      userResource, userQueryResource, constantResource, errorService,
      $routeParams, $scope, $rootScope, $location, page) {
    super(userResource, userQueryResource, $routeParams, $scope, $location);

    /** @private {!upvote.errornotifier.ErrorService} */
    this.errorService_ = errorService;
    /** @export {!angular.Scope} */
    this.rootScope = $rootScope;

    /** @export {string} */
    this.userRole = constantResource.get({'constant': 'userRole'});
    this.userRole['$promise'].catch((reason) => {
      this.errorService_.createToastFromError(reason);
    });

    /** @export {!Object} */
    this.form = Object.assign({}, UserController.EMPTY_FORM_);

    // Add save function to form
    this.form['save'] = () => {
      this.resource.save(this.form)['$promise']
          .then((results) => {
            this.id = results['id'];
            this.loadCard();
            this.showForm = false;
          })
          .catch((reason) => {
            this.errorService_.createDialogFromError(reason);
          });
    };

    /** @export {boolean} */
    this.showForm = false;

    page.title = 'Users';

    // Initialize the controller
    this.init();
  }

  /** @override */
  loadCard() {
    let cardPromise = super.loadCard();
    return (!cardPromise) ? cardPromise : cardPromise.then(() => {
      this.card['rootScope'] = this.rootScope;
    });
  }

  /**
   * When searching for an ID, try to append the domain if one wasn't provided.
   * @override
   */
  search() {
    if (this.queryData['searchBase'] == 'id') {
      let search = this.queryData['search'];
      if (search) {
        if (!search.includes('@')) {
          search += '@' + upvote.admin.app.constants.USER_EMAIL_DOMAIN;
        }
        this.selectItem(search);
      }
    } else {
      this.loadData();
    }
  }

  /**
   * Clear the contents and toggle the visibility of the form.
   * @export
   */
  toggleForm() {
    this.form = Object.assign(this.form, UserController.EMPTY_FORM_);
    this.showForm = !this.showForm;
  }
};
let UserController = upvote.admin.userpage.UserController;


/** @private @const {{id: string, roles: Array<string>}} */
UserController.EMPTY_FORM_ = {
  'id': '',
  'roles': []
};
});  // goog.scope
