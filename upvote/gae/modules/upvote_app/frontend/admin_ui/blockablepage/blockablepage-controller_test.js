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

goog.require('upvote.admin.blockablepage.BlockableController');
goog.require('upvote.admin.blockables.module');
goog.require('upvote.admin.votes.module');
goog.require('upvote.errornotifier.module');
goog.require('upvote.shared.Page');

describe('BlockableController', () => {
  let blockableResource, blockableQueryResource, voteCastResource, errorService,
      location, window, httpBackend, q, routeParams, rootScope, page;

  beforeEach(() => {
    module(upvote.admin.blockables.module.name);
    module(upvote.admin.votes.module.name);
    module(upvote.errornotifier.module.name);

    inject(
        (_blockableResource_, _blockableQueryResource_, _voteCastResource_,
         _errorService_, $location, $window, $httpBackend, $q, $rootScope) => {
          // Store injected components.
          blockableResource = _blockableResource_;
          blockableQueryResource = _blockableQueryResource_;
          voteCastResource = _voteCastResource_;
          errorService = _errorService_;
          location = $location;
          window = $window;
          httpBackend = $httpBackend;
          q = $q;
          rootScope = $rootScope;
          page = new upvote.shared.Page();

          // Create spies.
          spyOn(blockableResource, 'get');
          spyOn(blockableResource, 'reset');
          spyOn(blockableQueryResource, 'search');
          spyOn(voteCastResource, 'voteYes');
          spyOn(voteCastResource, 'voteNo');
          errorService.createDialogFromError =
              jasmine.createSpy('createDialogFromError');
          spyOn(window, 'open');

          routeParams = {'id': ''};
        });
  });

  afterEach(() => {
    httpBackend.verifyNoOutstandingExpectation();
    httpBackend.verifyNoOutstandingRequest();
  });

  let buildController = () =>
      new upvote.admin.blockablepage.BlockableController(
          blockableResource, blockableQueryResource, voteCastResource,
          errorService, routeParams, rootScope, rootScope, location, window,
          page);

  let resourcePromiseValue = (value) => {
    return {'$promise': q.when(value)};
  };

  beforeEach(() => {
    blockableResource.get.and.returnValue(resourcePromiseValue({}));
    blockableQueryResource.search.and.returnValue(resourcePromiseValue({}));
    routeParams['id'] = '';
  });

  describe('votes properly', () => {
    let fakeId = 'im21';
    let ctrl;

    beforeEach(() => {
      routeParams['id'] = fakeId;

      ctrl = buildController();
      rootScope.$apply();
    });

    it('when casting an upvote', () => {
      voteCastResource.voteYes.and.returnValue(resourcePromiseValue(null));

      ctrl.upVote();

      expect(voteCastResource.voteYes).toHaveBeenCalledWith({'id': fakeId});
    });

    it('when casting a downvote', () => {
      voteCastResource.voteNo.and.returnValue(resourcePromiseValue(null));

      ctrl.downVote();

      expect(voteCastResource.voteNo).toHaveBeenCalledWith({'id': fakeId});
    });

    it('when casting without a blockable', () => {
      routeParams['id'] = '';
      expect(voteCastResource.voteYes).not.toHaveBeenCalled();
      expect(voteCastResource.voteNo).not.toHaveBeenCalled();
    });

    it('when votes are reset', () => {
      ctrl.reset();

      expect(blockableResource.reset).toHaveBeenCalledWith({'id': fakeId});
    });
  });

  describe('navigates to the blockable page', () => {
    let fakeId = 'im21';
    let ctrl;

    beforeEach(() => {
      routeParams['id'] = fakeId;
    });

    it('for admins', () => {
      ctrl = buildController();
      rootScope.$apply();
      ctrl.goToBlockable(true);

      expect(window.open)
          .toHaveBeenCalledWith('/admin/blockables/' + fakeId, '_blank');
    });

    it('for users', () => {
      ctrl = buildController();
      rootScope.$apply();
      ctrl.goToBlockable(false);

      expect(window.open)
          .toHaveBeenCalledWith('/blockables/' + fakeId, '_blank');
    });
  });

  it('doesn\'t navigate if no blockable is selected', () => {
    let ctrl = buildController();
    rootScope.$apply();

    ctrl.goToBlockable(false);

    expect(window.open).not.toHaveBeenCalled();
  });
});
