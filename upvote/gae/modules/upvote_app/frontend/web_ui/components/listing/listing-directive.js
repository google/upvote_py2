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

goog.provide('upvote.listing.Listing');
goog.provide('upvote.listing.ListingCell');
goog.provide('upvote.listing.ListingHeader');
goog.provide('upvote.listing.ListingRow');

goog.require('upvote.app.constants');
goog.require('upvote.listing.ListingCellController');
goog.require('upvote.listing.ListingController');
goog.require('upvote.listing.ListingRowController');


/**
 * The directive for a listing.
 */
upvote.listing.Listing = class {
  constructor() {
    /** @export */
    this.restrict = 'E';

    /** @export */
    this.transclude = {
      'header': 'listingHeader',
      'body': 'listingBody',
    };

    /** @export */
    this.replace = true;
    /** @export */
    this.bindToController = true;
    /** @export */
    this.scope = {};
    /** @export */
    this.controller = upvote.listing.ListingController;
    /** @export */
    this.controllerAs = 'ctrl';
    /** @export */
    this.templateUrl = upvote.app.constants.STATIC_URL_PREFIX +
        'components/listing/listing.html';
  }

  /**
   * The link function for the directive.
   * @param {!angular.Scope} scope
   * @param {!angular.JQLite} element
   * @param {!angular.Attributes} attrs
   * @param {!upvote.listing.ListingController} listingController The directive's
   *   controller.
   * @export
   */
  link(scope, element, attrs, listingController) {
    let header = element.find('listing-header');
    if (header) {
      header.addClass('layout-row');
      header.addClass('flex');
    }
  }
};



/** The directive for a listing header. */
upvote.listing.ListingHeader = class {
  constructor() {
    /** @export */
    this.restrict = 'E';
    /** @export */
    this.require = '^uvListing';
    /** @export */
    this.transclude = true;
    /** @export */
    this.replace = true;
    /** @export */
    this.scope = {};
    /** @export */
    this.templateUrl = upvote.app.constants.STATIC_URL_PREFIX +
        'components/listing/listingheader.html';
  }

  /**
   * The link function for the directive.
   * @param {!angular.Scope} scope
   * @param {!angular.JQLite} element
   * @param {!angular.Attributes} attrs
   * @param {!upvote.listing.ListingController} listingController The controller
   *   of the parent directive.
   * @export
   */
  link(scope, element, attrs, listingController) {
    listingController.addClassList(element[0].classList, element[0].attributes);
  }
};


/** The for a listing row. */
upvote.listing.ListingRow = class {
  constructor() {
    /** @export */
    this.restrict = 'E';
    /** @export */
    this.require = '^uvListing';
    /** @export */
    this.transclude = true;
    /** @export */
    this.replace = true;
    /** @export */
    this.scope = {'onSelect': '&'};
    /** @export */
    this.templateUrl = upvote.app.constants.STATIC_URL_PREFIX +
        'components/listing/listingrow.html';
    /** @export */
    this.controller = upvote.listing.ListingRowController;
    /** @export */
    this.controllerAs = 'rowCtrl';
  }
};


/** The directive for a listing cell. */
upvote.listing.ListingCell = class {
  constructor() {
    /** @export */
    this.restrict = 'E';
    /** @export */
    this.require = ['^^uvListing', '^uvListingRow', 'uvListingCell'];
    /** @export */
    this.transclude = true;
    /** @export */
    this.replace = true;
    /** @export */
    this.scope = {};
    /** @export */
    this.templateUrl = upvote.app.constants.STATIC_URL_PREFIX +
        'components/listing/listingcell.html';
    /** @export */
    this.controller = upvote.listing.ListingCellController;
    /** @export */
    this.controllerAs = 'itemCtrl';
  };

  /**
   * The link function for the directive.
   * @param {!angular.Scope} scope
   * @param {!angular.JQLite} element
   * @param {!angular.Attributes} attrs
   * @param {!Array<Object>} controllers The controllers of all the involved
   *   directives.
   * @export
   */
  link(scope, element, attrs, controllers) {
    let listingCtrl = controllers[0];
    let rowCtrl = controllers[1];
    let itemCtrl = controllers[2];
    rowCtrl.addCell(itemCtrl);

    let classList = listingCtrl.getClasses(itemCtrl);
    for (let cls of classList) {
      element.addClass(cls);
    }
  }
};
