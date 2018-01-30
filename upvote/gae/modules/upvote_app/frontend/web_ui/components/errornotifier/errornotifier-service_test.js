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

goog.require('upvote.errornotifier.ErrorService');
goog.require('upvote.errornotifier.module');

goog.scope(() => {
const ErrorService = upvote.errornotifier.ErrorService;


describe('ErrorService', () => {
  let errorService, q, rootScope, mdDialog, mdDialogPreset, mdToast,
      mdToastPreset;

  beforeEach(/** @suppress {missingProperties} */ () => {
    angular.mock.module(upvote.errornotifier.module.name);

    angular.mock.inject(($mdDialog, $q, $rootScope) => {
      // Store injected components.
      mdDialog = $mdDialog;
      q = $q;
      rootScope = $rootScope;

      // Create spies.
      mdToastPreset = jasmine.createSpyObj('$mdToastPreset', [
        'textContent',
        'action',
        'highlightAction',
        'position',
        'hideDelay',
      ]);
      mdToastPreset.textContent.and.returnValue(mdToastPreset);
      mdToastPreset.action.and.returnValue(mdToastPreset);
      mdToastPreset.highlightAction.and.returnValue(mdToastPreset);
      mdToastPreset.position.and.returnValue(mdToastPreset);
      mdToastPreset.hideDelay.and.returnValue(mdToastPreset);

      mdToast = jasmine.createSpyObj('$mdToast', ['simple', 'show']);
      mdToast.simple.and.returnValue(mdToastPreset);

      mdDialogPreset = jasmine.createSpyObj('$mdDialogPreset', [
        'htmlContent',
        'title',
        'ok',
      ]);
      mdDialogPreset.htmlContent.and.returnValue(mdDialogPreset);
      mdDialogPreset.title.and.returnValue(mdDialogPreset);
      mdDialogPreset.ok.and.returnValue(mdDialogPreset);

      mdDialog = jasmine.createSpyObj('$mdDialog', ['alert', 'show']);
      mdDialog.alert.and.returnValue(mdDialogPreset);
    });
  });

  let buildService = () => new ErrorService(mdDialog, mdToast);

  describe('should display', () => {
    beforeEach(() => {
      errorService = buildService();
    });

    it('a simple toast', () => {
      errorService.createSimpleToast('foo');
      rootScope.$apply();

      expect(mdToast.show).toHaveBeenCalled();
      expect(mdToastPreset.textContent).toHaveBeenCalledWith('foo');
    });

    describe('a more info toast', () => {
      it('and call the callback with nothing after a delay', () => {
        let aSpy = jasmine.createSpy('a');
        mdToast.show.and.returnValue(q.when());
        errorService.createMoreInfoToast('foo', aSpy);
        rootScope.$apply();

        expect(aSpy).toHaveBeenCalledWith(undefined);
        expect(mdToastPreset.textContent).toHaveBeenCalledWith('foo');
      });

      it('and call the callback with "ok" after a delay', () => {
        let aSpy = jasmine.createSpy('a');
        mdToast.show.and.returnValue(q.when('ok'));
        errorService.createMoreInfoToast('foo', aSpy);
        rootScope.$apply();

        expect(aSpy).toHaveBeenCalledWith('ok');
        expect(mdToastPreset.textContent).toHaveBeenCalledWith('foo');
      });
    });

    it('an HTTP Error toast', () => {
      errorService.createDialogFromError =
          jasmine.createSpy('createDialogFromError');
      mdToast.show.and.returnValue(q.when('ok'));
      let errorConfig = {
        'status': 400,
        'statusText': 'Bad Request',
      };
      errorService.createToastFromError(errorConfig);
      rootScope.$apply();

      expect(mdToastPreset.textContent)
          .toHaveBeenCalledWith('HTTP Error 400 Bad Request');
      expect(errorService.createDialogFromError)
          .toHaveBeenCalledWith(errorConfig);
    });

    describe('an HTTP Error dialog', () => {
      it('if there are query params', () => {
        let errorConfig = {
          'status': 400,
          'statusText': 'Bad Request',
          'config': {'url': '/', 'params': {'a': 'b', 'c': 'd'}},
          'data': 'foo'
        };
        errorService.createDialogFromError(errorConfig);
        rootScope.$apply();

        expect(mdDialogPreset.title)
            .toHaveBeenCalledWith('HTTP Error 400 Bad Request');
        expect(mdDialogPreset.htmlContent).toHaveBeenCalled();
        let msg = mdDialogPreset.htmlContent.calls.mostRecent().args[0];
        if (msg.includes('?a')) {
          expect(msg).toContain('URL: /?a=b&c=d');
        } else {
          expect(msg).toContain('URL: /?c=d&a=b');
        }
        expect(msg).toContain('Message: foo');
      });

      it('if there aren\'t query params', () => {
        let errorConfig = {
          'status': 400,
          'statusText': 'Bad Request',
          'config': {'url': '/'},
          'data': ''
        };
        errorService.createDialogFromError(errorConfig);
        rootScope.$apply();

        expect(mdDialogPreset.htmlContent).toHaveBeenCalled();
        let msg = mdDialogPreset.htmlContent.calls.mostRecent().args[0];
        expect(msg).toContain('URL: /<br>');
      });
    });
  });
});
});  // goog.scope
