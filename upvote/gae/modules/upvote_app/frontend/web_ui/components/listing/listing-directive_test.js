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

goog.require('goog.dom');
goog.require('upvote.app.module');

goog.scope(() => {

describe('upvote.listing', () => {
  const templateHtml =
      ('<uv-listing>' +
       '  <listing-header>' +
       '    <uv-listing-header flex="25">Field1</uv-listing-header>' +
       '    <uv-listing-header flex-gt-md="10" flex="15">Field2' +
       '    </uv-listing-header>' +
       '  </listing-header>' +
       '  <listing-body>' +
       '    <uv-listing-row>' +
       '      <uv-listing-cell>Item1 Field1</uv-listing-cell>' +
       '      <uv-listing-cell>Item1 Field2</uv-listing-cell>' +
       '    </uv-listing-row>' +
       '    <uv-listing-row>' +
       '      <uv-listing-cell>Item2 Field1</uv-listing-cell>' +
       '      <uv-listing-cell>Item2 Field2</uv-listing-cell>' +
       '    </uv-listing-row>' +
       '  </listing-body>' +
       '</uv-listing>');
  let scope;
  let listingElement;

  beforeEach(() => {
    module(upvote.templates.module.name);
    module(upvote.app.module.name);

    inject(($rootScope, $compile) => {
      scope = $rootScope.$new();
      listingElement = $compile(templateHtml)(scope);
      scope.$apply();
    });
  });

  it('should have appropriate number of headers', () => {
    let headerElement = listingElement.find('listing-header');
    let cells =
        goog.dom.getElementsByClass('uv-listing-cell', headerElement[0]);
    expect(cells.length).toBe(2);
  });

  it('should have appropriate number of rows and cells in body with correct ' +
         'classes',
     () => {
       let bodyElement = listingElement.find('listing-body');
       let rows = bodyElement.find('md-list-item');
       expect(rows.length).toBe(2);
       for (let row of rows) {
         let cells = goog.dom.getElementsByClass('uv-listing-cell', row);
         expect(cells.length).toBe(2);
         let cell0 = angular.element(cells[0]);
         expect(cell0.hasClass('flex-25')).toBe(true);
         let cell1 = angular.element(cells[1]);
         expect(cell1.hasClass('flex-15')).toBe(true);
         expect(cell1.hasClass('flex-gt-md-10')).toBe(true);
       }
     });
});
});  // goog.scope
