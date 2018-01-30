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

goog.provide('upvote.listing.ListingCellController');
goog.provide('upvote.listing.ListingController');
goog.provide('upvote.listing.ListingRowController');

goog.scope(() => {

/**
 * The controller for the listing directive.
 */
upvote.listing.ListingController = class {
  constructor() {
    /** @private {!Array<!Array<string>>} */
    this.classesLists_ = [];
  }

  /**
   * Returns whether the provided class name should be copied onto the element.
   * @param {!string} className The CSS classes to (maybe) add.
   * @return {boolean} Whether the class name should be copied
   * @private
   */
  copyClassName_(className) {
    return (
        ListingController.COPIED_CLASSES_.includes(className) ||
        ListingController.COPIED_PREFIX_.reduce(
            (acc, val) => acc || className.startsWith(val), false));
  }

  /**
   * Adds the list of relevant CSS classes from a header to the listing.
   * @param {!Array<string>} classes The CSS classes to add.
   * @param {!NamedNodeMap<!Attr>} attributes The element's attributes.
   * @export
   */
  addClassList(classes, attributes) {
    let classList = [];
    for (let cls of classes) {
      if (this.copyClassName_(cls)) {
        classList.push(cls);
      }
    }
    for (let attr of attributes) {
      if (this.copyClassName_(attr.name)) {
        classList.push(attr.name + '-' + attr.value);
      }
    }
    this.classesLists_.push(classList);
  }

  /**
   * Gets the list of CSS classes for a given cell.
   * @param {!upvote.listing.ListingCellController} cellCtrl The controller
   *   for the cell to get classes for.
   * @return {!Array<string>} The list of classes for the given cell.
   * @export
   */
  getClasses(cellCtrl) {
    if (cellCtrl.cellNum < this.classesLists_.length) {
      return this.classesLists_[cellCtrl.cellNum];
    } else {
      return [];
    }
  }
};
const ListingController = upvote.listing.ListingController;

/** @const @private {!Array<string>} */
ListingController.COPIED_CLASSES_ = ['flex', 'hide', 'show'];

/** @const @private {!Array<string>} */
ListingController.COPIED_PREFIX_ = ['flex-', 'show-', 'hide-'];


/**
 * The controller for the listing row directive.
 */
upvote.listing.ListingRowController = class {
  constructor() {
    this.numCells_ = 0;
  }

  /**
   * Handles adding cell to the given row.
   * @param {!upvote.listing.ListingCellController} cellCtrl The controller for
   *   the added cell.
   * @export
   */
  addCell(cellCtrl) {
    cellCtrl.cellNum = this.numCells_++;
  };
};


/**
 * The controller for the listing cell directive.
 */
upvote.listing.ListingCellController = class {
  constructor() {
    /**
     * The number of the cell in a row.
     * @type {number}
     */
    this.cellNum;
  }
};
});  // goog.scope
