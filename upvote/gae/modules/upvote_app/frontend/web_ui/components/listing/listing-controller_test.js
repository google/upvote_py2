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

goog.setTestOnly();

goog.require('upvote.listing.ListingCellController');
goog.require('upvote.listing.ListingController');
goog.require('upvote.listing.ListingRowController');

goog.scope(() => {

describe('Listing Controllers', () => {
  const ListingController = upvote.listing.ListingController;
  const ListingRowController = upvote.listing.ListingRowController;
  const ListingCellController = upvote.listing.ListingCellController;
  let controller;
  let listingCtrl;
  let listingRowCtrl;

  beforeEach(inject(($controller) => {
    controller = $controller;
    listingCtrl = controller(ListingController);
    listingRowCtrl = controller(ListingRowController);
  }));

  describe('Listing Row Controller', () => {
    it('should hanlde adding cells', () => {
      let ctrls = [];
      for (let i = 0; i < 3; i++) {
        let ctrl = controller(ListingCellController);
        ctrls.push(ctrl);
        listingRowCtrl.addCell(ctrl);
      }
      for (let i = 0; i < 3; i++) {
        expect(ctrls[i].cellNum).toBe(i);
      }
    });
  });

  describe('Listing Controller', () => {
    it('should add and retrieve appropriate classes', () => {
      let cellCtrl = controller(ListingCellController);
      listingRowCtrl.addCell(cellCtrl);
      listingCtrl.addClassList(
          [
            'show', 'flex-gd-sm', 'flex', 'should-skip', 'hide',
            'flexshouldskip'
          ],
          []);
      let classes = listingCtrl.getClasses(cellCtrl);
      expect(classes).toEqual(['show', 'flex-gd-sm', 'flex', 'hide']);
    });
  });
});
});  // goog.scope
