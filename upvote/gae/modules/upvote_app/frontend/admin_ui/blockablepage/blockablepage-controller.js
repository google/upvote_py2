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

goog.provide('upvote.admin.blockablepage.BlockableController');

goog.require('upvote.admin.app.constants');
goog.require('upvote.admin.lib.controllers.ModelController');
goog.require('upvote.app.constants');
goog.require('upvote.errornotifier.ErrorService');
goog.require('upvote.shared.Page');

goog.scope(() => {
const ModelController = upvote.admin.lib.controllers.ModelController;

/** Blockable model controller. */
upvote.admin.blockablepage.BlockableController = class extends ModelController {
  /**
   * @param {!angular.Resource} blockableResource
   * @param {!angular.Resource} blockableQueryResource
   * @param {!angular.Resource} voteCastResource
   * @param {!upvote.errornotifier.ErrorService} errorService
   * @param {!angular.$routeParams} $routeParams
   * @param {!angular.Scope} $scope
   * @param {!angular.Scope} $rootScope
   * @param {!angular.$location} $location
   * @param {!angular.$window} $window
   * @param {!upvote.shared.Page} page Details about the active webpage
   * @ngInject
   */
  constructor(
      blockableResource, blockableQueryResource, voteCastResource, errorService,
      $routeParams, $scope, $rootScope, $location, $window, page) {
    super(
        blockableResource, blockableQueryResource, $routeParams, $scope,
        $location);

    /** @private {!angular.Resource} */
    this.voteCastResource_ = voteCastResource;
    /** @private {!upvote.errornotifier.ErrorService} */
    this.errorService_ = errorService;
    /** @private {!angular.$window} */
    this.window_ = $window;
    /** @export {!angular.Scope} */
    this.rootScope = $rootScope;

    /** @export {!Object<string, !upvote.admin.lib.controllers.Field>} */
    this.fields = BlockableController.BASE_FIELDS_;
    /** @private {!Object<string, !upvote.admin.lib.controllers.Type>} */
    this.defaultTypes_ = angular.copy(ModelController.DEFAULT_TYPES);
    this.defaultTypes_['all']['value'] = 'all';

    /** @export {!Object} */
    this.form = {
      'id': '',
      'fileName': '',
      'publisher': '',
      'flagged': false,
      'type': 'SANTA_BINARY',
      'notes': 'Manually Entered.'
    };

    /** @export {boolean} */
    this.showForm = false;
    /** @export {boolean} */
    this.showSearchBase = false;

    page.title = 'Blockables';

    // Initialize the controller
    this.init();
  }

  /** @protected @override */
  init() {
    super.init();

    // Override the value for 'all' platforms because the blockables API route
    // expects the platform argument to be non-empty e.g. '/all/binaries'.
    // Then, re-request search results to actually get results.
    this.platforms['all']['value'] = 'all';
    this.requestData['platform'] = this.platforms['all']['value'];
    this.updateOptions();
    this.loadData();

    // Add a save function to the form
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
  }

  /** @override */
  loadCard() {
    let cardPromise = super.loadCard();
    return (!cardPromise) ? cardPromise : cardPromise.then(() => {
      this.card['rootScope'] = this.rootScope;
    });
  }

  /**
   * Navigates to the blockable page.
   * @param {boolean} adminView If should return the admin link.
   * @export
   */
  goToBlockable(adminView) {
    if (this.id) {
      // Add the prefix for admin or non-admin sections of the app
      let appPrefix = adminView ? upvote.admin.app.constants.URL_PREFIX :
                                  upvote.app.constants.URL_PREFIX;

      // Open url in a new window
      this.window_.open(appPrefix + 'blockables/' + this.id, '_blank');
    }
  }

  /** @override */
  updateToAll() {
    this.types = this.defaultTypes_;
    this.requestData['type'] = this.types['all']['value'];
    this.fields = BlockableController.BASE_FIELDS_;
  }

  /** @override */
  updateToBit9() {
    this.types = {
      'binary': {'displayName': 'Binaries', 'value': 'binaries'},
      'certificate': {'displayName': 'Certificates', 'value': 'certificates'},
    };

    // Set the currently selected type (default to Binary).
    let bit9TypeValues =
        Object.keys(this.types).map((key) => this.types[key]['value']);
    if (!bit9TypeValues.includes(this.requestData['type'])) {
      this.requestData['type'] = this.types['binary']['value'];
    }

    if (this.requestData['type'] == this.types['binary']['value']) {
      this.fields = Object.assign({}, BlockableController.BASE_FIELDS_, {
        'file_type': {'displayName': 'File Type', 'value': 'file_type'},
        'md5': {'displayName': 'md5', 'value': 'md5'},
        'sha1': {'displayName': 'SHA-1', 'value': 'sha1'},
      });
    } else if (this.requestData['type'] == this.types['certificate']['value']) {
      this.fields = Object.assign({}, BlockableController.BASE_FIELDS_, {});
    }
  }

  /** @override */
  updateToSanta() {
    this.types = {
      'binary': {'displayName': 'Binaries', 'value': 'binaries'},
      'certificate': {'displayName': 'Certificates', 'value': 'certificates'},
      'package': {'displayName': 'Bundles', 'value': 'packages'},
    };

    // Set the currently selected type (default to Binary).
    let santaTypeValues =
        Object.keys(this.types).map((key) => this.types[key]['value']);
    if (!santaTypeValues.includes(this.requestData['type'])) {
      this.requestData['type'] = this.types['binary']['value'];
    }

    if (this.requestData['type'] == this.types['binary']['value']) {
      this.fields = Object.assign({}, BlockableController.BASE_FIELDS_, {
        'bundle_id': {'displayName': 'Bundle ID', 'value': 'bundle_id'},
        'cert_sha256': {'displayName': 'Cert SHA-256', 'value': 'cert_sha256'},
      });
    } else if (this.requestData['type'] == this.types['certificate']['value']) {
      this.fields = Object.assign({}, BlockableController.BASE_FIELDS_, {
        'common_name': {'displayName': 'Common Name', 'value': 'common_name'},
        'organization':
            {'displayName': 'Organization', 'value': 'organization'},
      });
    } else if (this.requestData['type'] == this.types['package']['value']) {
      this.fields = Object.assign({}, BlockableController.BASE_FIELDS_, {
        'name': {'displayName': 'Name', 'value': 'name'},
        'bundle_id': {'displayName': 'Bundle ID', 'value': 'bundle_id'},
        'version': {'displayName': 'Version', 'value': 'version'},
        'short_version':
            {'displayName': 'Short Version', 'value': 'short_version'},
        'cert_sha256': {'displayName': 'Cert SHA-256', 'value': 'cert_id'},
      });
    }
  }

  /**
   * Upvote the current Blockable
   * @export
   */
  upVote() {
    this.castVote_(true);
  }

  /**
   * Downvote the current Blockable
   * @export
   */
  downVote() {
    this.castVote_(false);
  }

  /**
   * Reset the current Blockable
   * @export
   */
  reset() {
    if (this.id) {
      this.resource['reset']({'id': this.id});
    }
  }

  /**
   * Cast a vote on the current Blockable
   * @param {boolean} isUpVote Whether to cast an upvote (vs a downvote)
   * @private
   */
  castVote_(isUpVote) {
    if (this.id) {
      let castFunction = isUpVote ? this.voteCastResource_['voteYes'] :
                                    this.voteCastResource_['voteNo'];
      castFunction({'id': this.id})['$promise']
          .then(() => {
            this.loadCard();
          })
          .catch((reason) => {
            this.errorService_.createDialogFromError(reason);
          });
    }
  }

  /** @override */
  searchSelected() {
    super.searchSelected();
    this.showForm = false;
  }

  /**
   * Toggle the form visibility.
   * @export
   */
  toggleForm() {
    this.showForm = true;
    this.showSearchBase = false;
  }
};
let BlockableController = upvote.admin.blockablepage.BlockableController;

/** @private {!Object<string, !upvote.admin.lib.controllers.Field>} */
BlockableController.BASE_FIELDS_ = {
  'id': {'displayName': 'ID', 'value': 'id'},
  'fileName': {'displayName': 'File Name', 'value': 'fileName'},
  'publisher': {'displayName': 'Publisher', 'value': 'publisher'},
  'productName': {'displayName': 'Product Name', 'value': 'productName'}
};
});  // goog.scope
