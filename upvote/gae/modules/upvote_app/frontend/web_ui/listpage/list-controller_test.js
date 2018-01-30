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

goog.require('upvote.app.constants');
goog.require('upvote.errornotifier.module');
goog.require('upvote.events.module');
goog.require('upvote.listpage.BlockableListController');
goog.require('upvote.shared.Page');

goog.scope(() => {
const BlockableListCtrl = upvote.listpage.BlockableListController;


describe('Blockable List Controller', () => {
  let eventQueryResource, blockableService, errorService, location, q,
      rootScope, page;
  let ctrl;

  beforeEach(/** @suppress {missingProperties} */ () => {
    angular.mock.module(upvote.blockables.module.name);
    angular.mock.module(upvote.events.module.name);
    angular.mock.module(upvote.errornotifier.module.name);

    angular.mock.inject(
        (_eventQueryResource_, _blockableService_, _errorService_, $location,
         $q, $rootScope) => {
          // Store injected components.
          eventQueryResource = _eventQueryResource_;
          blockableService = _blockableService_;
          errorService = _errorService_;
          location = $location;
          q = $q;
          rootScope = $rootScope;
          page = new upvote.shared.Page();

          // Create spies.
          spyOn(eventQueryResource, 'getPage');
          blockableService.getPending = jasmine.createSpy('getPending');
          errorService.createToastFromError =
              jasmine.createSpy('createToastFromError');
          errorService.createSimpleToast =
              jasmine.createSpy('createSimpleToast');
        });
  });

  // Set the default initialization to be one without results
  beforeEach(() => {
    setEvent({
      'content': [],
      'cursor': 'foo',
      'more': false,
    });
    setPendingState(false);
  });

  let buildController = () => new BlockableListCtrl(
      eventQueryResource, blockableService, errorService, location, q, page);

  let setEvent = (event_) => {
    if (event_ != null) {
      eventQueryResource['getPage']['and']['returnValue'](
          {'$promise': q.when(event_)});
    } else {
      eventQueryResource['getPage']['and']['returnValue'](
          {'$promise': q.reject()});
    }
  };

  let setPendingState = (isPending) => {
    if (isPending != null) {
      blockableService.getPending['and']['returnValue'](
          q.resolve({'data': isPending}));
    } else {
      blockableService.getPending['and']['returnValue'](q.reject());
    }
  };

  let genEventWithContext = (blockableId, hostId) => {
    return {
      'blockable': {'id': blockableId},
      'event': {},
      'host': {'id': hostId},
      'vote': {}
    };
  };

  describe('should display an error notifiction', () => {
    it('when initialization fails', () => {
      setEvent(null);

      ctrl = buildController();
      rootScope.$apply();

      expect(errorService.createToastFromError).toHaveBeenCalled();
    });
  });

  describe('should initialize the data list', () => {
    it('when there are no results', () => {
      ctrl = buildController();
      rootScope.$apply();

      expect(eventQueryResource['getPage']['calls'].count()).toEqual(1);
      expect(ctrl.results['more']).toBe(false);
      expect(ctrl.results['content']).toEqual([]);
    });

    describe('with a single page of result', () => {
      let content;

      beforeEach(() => {
        content = [];
        for (let i = 0; i < 10; i++) {
          content.push(genEventWithContext('a' + i, ''));
        }
      });

      it('when there is more than one page of results', () => {
        setEvent({
          content,
          'cursor': 'foo',
          'more': true,  // Fake another page by setting more to true
        });

        ctrl = buildController();
        rootScope.$apply();

        expect(eventQueryResource['getPage']['calls'].count()).toEqual(1);
        expect(ctrl.results['content'].length).toEqual(10);
      });

      it('when there is a exactly one page of result', () => {
        setEvent({
          content,
          'cursor': '',
          'more': false,
        });

        ctrl = buildController();
        rootScope.$apply();

        expect(eventQueryResource['getPage']['calls'].count()).toEqual(1);
        expect(ctrl.results['content'].length).toEqual(10);
        expect(ctrl.results['content'][0]['isPending']).toBe(false);
      });
    });
  });

  it('should load more and report accurate state when doing so', () => {
    ctrl = buildController();
    rootScope.$apply();

    // Set the loadMore response.
    setEvent({
      'content': [],
      'cursor': '',
      'more': false,
    });

    // Test isLoadingMore states
    expect(ctrl.isLoadingMore).toBe(false);
    ctrl.loadMore();
    expect(ctrl.isLoadingMore).toBe(true);
    // Resolve the loadMore.
    rootScope.$apply();
    // Verify isLoadingMore has returned to false.
    expect(ctrl.isLoadingMore).toBe(false);
    expect(eventQueryResource['getPage']['calls'].count()).toEqual(2);
  });

  it('should get the proper blockable class', () => {
    ctrl = buildController();
    let blockableClass = ctrl.getBlockableClass(
        {'operatingSystemFamily': upvote.app.constants.PLATFORMS.MACOS});
    expect(blockableClass).toMatch(/santa/);

    blockableClass = ctrl.getBlockableClass(
        {'operatingSystemFamily': upvote.app.constants.PLATFORMS.WINDOWS});
    expect(blockableClass).toMatch(/bit9/);

    blockableClass =
        ctrl.getBlockableClass({'operatingSystemFamily': 'Android'});
    expect(blockableClass).toEqual('');

    blockableClass = ctrl.getBlockableClass(null);
    expect(blockableClass).toEqual('');
  });

  it('should get the proper platform image url', () => {
    ctrl = buildController();
    let imgUrl = ctrl.getPlatformImageUrl(
        {'operatingSystemFamily': upvote.app.constants.PLATFORMS.MACOS});
    expect(imgUrl).toMatch(/apple/);

    imgUrl = ctrl.getPlatformImageUrl(
        {'operatingSystemFamily': upvote.app.constants.PLATFORMS.WINDOWS});
    expect(imgUrl).toMatch(/windows/);

    imgUrl = ctrl.getPlatformImageUrl({'operatingSystemFamily': 'Android'});
    expect(imgUrl).toEqual('');

    imgUrl = ctrl.getPlatformImageUrl(null);
    expect(imgUrl).toEqual('');
  });

  it('should get the proper platform alt text', () => {
    ctrl = buildController();
    let altText = ctrl.getPlatformImageAltText(
        {'operatingSystemFamily': upvote.app.constants.PLATFORMS.MACOS});
    expect(altText).toMatch(/Mac/);

    altText = ctrl.getPlatformImageAltText(
        {'operatingSystemFamily': upvote.app.constants.PLATFORMS.WINDOWS});
    expect(altText).toMatch(/Windows/);

    altText =
        ctrl.getPlatformImageAltText({'operatingSystemFamily': 'Android'});
    expect(altText).toEqual('');

    altText = ctrl.getPlatformImageAltText(null);
    expect(altText).toEqual('');
  });

  describe('should, when a blockable is selected, ', () => {
    it('navigate to the associated blockable\'s detail page', () => {
      ctrl = buildController();

      let blockable = {'id': 'abc'};
      ctrl.goToBlockable(blockable);
      expect(location.path()).toEqual('/blockables/abc');
    });

    it('toast an error message if the blockable is invalid', () => {
      ctrl = buildController();

      ctrl.goToBlockable(null);
      expect(errorService.createSimpleToast).toHaveBeenCalled();
    });
  });
});
});  // goog.scope
