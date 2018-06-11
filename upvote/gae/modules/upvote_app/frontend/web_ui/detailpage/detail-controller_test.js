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

goog.require('upvote.blockables.module');
goog.require('upvote.detailpage.BlockableDetailsController');
goog.require('upvote.errornotifier.module');
goog.require('upvote.events.module');
goog.require('upvote.settings.module');
goog.require('upvote.shared.constants.BlockableState');
goog.require('upvote.shared.constants.UserRole');
goog.require('upvote.stickystepper.module');
goog.require('upvote.users.module');
goog.require('upvote.votes.module');

goog.scope(() => {
const BlockableDetailsCtrl = upvote.detailpage.BlockableDetailsController;
const BlockableState = upvote.shared.constants.BlockableState;
const UserRole = upvote.shared.constants.UserRole;


describe('Detail Controller', () => {
  const templateHtml =
      ('<div ng-controller="Ctrl as ctrl">' +
       '  <md-stepper md-vertical="true" md-linear="true" id="voting-stepper">' +
       '    <md-step md-label="Step 1"></md-step>' +
       '    <md-step md-label="Step 2"></md-step>' +
       '    <md-step md-label="Step 3"></md-step>' +
       '    <md-step md-label="Step 4"></md-step>' +
       '  </md-stepper>' +
       '</div');
  let blockableResource, blockableService, recentEventResource, userResource,
      voteCastResource, settingResource, errorService, q, routeParams, timeout,
      mdDialog, mdComponentRegistry, rootScope, compile;
  let ctrl, scope;

  // clang-format off
  let testModule = angular.module('testModule', [
    upvote.blockables.module.name,
    upvote.events.module.name,
    upvote.users.module.name,
    upvote.votes.module.name,
    upvote.settings.module.name,
    upvote.stickystepper.module.name,
    upvote.errornotifier.module.name,
    'ngRoute']).controller('Ctrl', BlockableDetailsCtrl);
  // clang-format on

  beforeEach(/** @suppress {missingProperties} */ () => {
    angular.mock.module(upvote.blockables.module.name);
    angular.mock.module(upvote.events.module.name);
    angular.mock.module(upvote.users.module.name);
    angular.mock.module(upvote.votes.module.name);
    angular.mock.module(upvote.settings.module.name);
    angular.mock.module(upvote.stickystepper.module.name);
    angular.mock.module(upvote.errornotifier.module.name);
    angular.mock.module('ngRoute');

    angular.mock.module(testModule.name);
    angular.module('upvote.app.module', []).value('page', {title: ''});
    angular.mock.module('upvote.app.module');

    angular.mock.inject(
        (_blockableResource_, _blockableService_, _recentEventResource_,
         _userResource_, _voteCastResource_, _settingResource_, _errorService_,
         $q, $routeParams, $timeout, $mdDialog, $mdComponentRegistry,
         $rootScope, $compile) => {
          // Store injected components.
          blockableResource = _blockableResource_;
          blockableService = _blockableService_;
          recentEventResource = _recentEventResource_;
          userResource = _userResource_;
          voteCastResource = _voteCastResource_;
          settingResource = _settingResource_;
          errorService = _errorService_;
          q = $q;
          routeParams = $routeParams;
          timeout = $timeout;
          mdDialog = $mdDialog;
          mdComponentRegistry = $mdComponentRegistry;

          rootScope = $rootScope;
          compile = $compile;
        });

    // Create spies.
    spyOn(blockableResource, 'get');
    blockableService.getPackageContents =
        jasmine.createSpy('getPackageContents');
    blockableService.getPending = jasmine.createSpy('getPending');
    blockableService.getInstallerPending =
        jasmine.createSpy('getInstallerPending');
    blockableService.setInstallerForce = jasmine.createSpy('setInstallerForce');
    spyOn(recentEventResource, 'get');
    spyOn(userResource, 'getSelf');
    spyOn(voteCastResource, 'voteYes');
    spyOn(voteCastResource, 'voteNo');
    spyOn(voteCastResource, 'get');
    spyOn(settingResource, 'get');
    spyOn(mdDialog, 'show');

    // Set all responses to their defaults.
    setBlockable({});
    setPackageContents([]);
    setPendingState(false);
    setInstallerPendingState(false);
    setRecentEvent({});
    setVote({});
    setYesVoteCast({}, {});
    setNoVoteCast({}, {});
    setUser({});
    setSettings({}, {});
    mdDialog['show']['and']['returnValue'](q.when({}));

    // NOTE: These properties do not get properly stubbed out with
    // spyOn when property renaming is enabled. Since ErrorService is a struct,
    // its method names get rewritten.
    errorService.createDialogFromError =
        jasmine.createSpy('createDialogFromError');
    errorService.createToastFromError =
        jasmine.createSpy('createToastFromError');
    errorService.createSimpleToast = jasmine.createSpy('createSimpleToast');
  });

  let defaultVote = {
    'id': 'InEffect',
    'wasYesVote': true,
    'isVotingAllowed': true
  };

  let defaultBlockable = {
    'id': 'abcd',
    'class_': ['Blockable', 'Binary', 'SantaBinary'],
    'state': 'UNTRUSTED',
    'isVotingAllowed': true
  };

  let defaultSantaBundle = Object.assign({}, defaultBlockable, {
    'class_': ['Blockable', 'Package', 'SantaBundle'],
  });

  let defaultBit9Blockable = Object.assign({}, defaultBlockable, {
    'class_': ['Blockable', 'Binary', 'Bit9Binary'],
  });

  let defaultUser = {
    'id': 'aUser@foo.com',
    'isAdmin': false,
    'name': 'aUser',
    'roles': [],
    'recordedDt': new Date().toISOString(),
    'lastVoteDt': null,
    'voteWeight': 1
  };

  let defaultVotingThresholds = {};
  defaultVotingThresholds[BlockableState['APPROVED_FOR_LOCAL_WHITELISTING']] =
      2;
  defaultVotingThresholds[BlockableState['GLOBALLY_WHITELISTED']] = 50;

  let defaultVotingWeights = {};
  defaultVotingWeights[UserRole['USER']] = 1;
  defaultVotingWeights[UserRole['TRUSTED_USER']] = 3;

  let setBlockable = (updatedProperties) => {
    if (!!updatedProperties) {
      blockableResource['get']['and']['returnValue']({
        '$promise':
            q.when(Object.assign({}, defaultBlockable, updatedProperties))
      });
    } else {
      blockableResource['get']['and']['returnValue']({'$promise': q.reject()});
    }
  };

  let setBit9Blockable = (updatedProperties) => {
    if (!!updatedProperties) {
      setBlockable(Object.assign({}, defaultBit9Blockable, updatedProperties));
    } else {
      setBlockable(updatedProperties);
    }
  };

  let setPendingState = (isPending) => {
    if (isPending !== null) {
      blockableService.getPending['and']['returnValue'](
          q.when({'data': isPending}));
    } else {
      blockableService.getPending['and']['returnValue'](q.reject());
    }
  };

  let setInstallerPendingState = (isPending) => {
    if (isPending !== null) {
      blockableService.getInstallerPending['and']['returnValue'](
          q.when({'data': isPending}));
    } else {
      blockableService.getInstallerPending['and']['returnValue'](q.reject());
    }
  };

  let setSetInstallerForce = (isPending) => {
    if (isPending !== null) {
      blockableService.setInstallerForce['and']['returnValue'](
          q.when({'data': isPending}));
    } else {
      blockableService.setInstallerForce['and']['returnValue'](q.reject());
    }
  };

  let setRecentEvent = (eventCtx) => {
    if (!!eventCtx) {
      recentEventResource['get']['and']['returnValue'](
          {'$promise': q.when(eventCtx)});
    } else {
      recentEventResource['get']['and']['returnValue'](
          {'$promise': q.reject()});
    }
  };

  let setPackageContents = (content) => {
    if (content !== null) {
      blockableService.getPackageContents['and']['returnValue'](
          q.when({'data': content}));
    } else {
      blockableService.getPackageContents['and']['returnValue'](q.reject());
    }
  };

  let setVote = (updatedProperties) => {
    if (!!updatedProperties) {
      voteCastResource['get']['and']['returnValue']({
        '$promise': q.when(Object.assign({}, defaultVote, updatedProperties))
      });
    } else {
      voteCastResource['get']['and']['returnValue']({'$promise': q.reject()});
    }
  };

  let setYesVoteCast = (updatedBlockableProperties, updatedVoteProperties) => {
    setVoteCast_(true, updatedBlockableProperties, updatedVoteProperties);
  };
  let setNoVoteCast = (updatedBlockableProperties, updatedVoteProperties) => {
    let props = Object.assign({'wasYesVote': false}, updatedVoteProperties);
    setVoteCast_(false, updatedBlockableProperties, props);
  };
  let setVoteCast_ =
      (isYesVote, updatedBlockableProperties, updatedVoteProperties) => {
        let voteCastSpy = voteCastResource[isYesVote ? 'voteYes' : 'voteNo'];
        if (!!updatedBlockableProperties || !!updatedVoteProperties) {
          let voteCastResponse = {
            '$promise': q.when({
              'blockable': Object.assign(
                  {}, defaultBlockable, updatedBlockableProperties),
              'vote': Object.assign({}, defaultVote, updatedVoteProperties)
            })
          };
          voteCastSpy['and']['returnValue'](voteCastResponse);
        } else {
          voteCastSpy['and']['returnValue']({'$promise': q.reject()});
        }
      };

  let setUser = (updatedProperties) => {
    userResource['getSelf']['and']['returnValue']({
      '$promise': q.when(Object.assign({}, defaultUser, updatedProperties))
    });
  };

  let setSettings = (thresholdProperties, weightProperties) => {
    let votingThresholds =
        Object.assign({}, defaultVotingThresholds, thresholdProperties);
    let votingWeights =
        Object.assign({}, defaultVotingWeights, weightProperties);
    settingResource['get']['and']['callFake']((obj) => {
      if (obj['setting'] == 'votingThresholds') {
        return {'$promise': q.when(votingThresholds)};
      } else if (obj['setting'] == 'votingWeights') {
        return {'$promise': q.when(votingWeights)};
      }
    });
  };

  let getStepper = () => mdComponentRegistry.get('voting-stepper');

  let buildController = () => {
    scope = rootScope.$new();
    let element = compile(angular.element(templateHtml))(scope);
    return element.controller();
  };

  describe('should load a custom 404 message', () => {
    it('if the blockable does not exist', () => {
      blockableResource['get']['and']['returnValue'](
          {'$promise': q.reject({'status': 404})});

      ctrl = buildController();
      scope.$apply();

      expect(ctrl.blockableLoaded).toBe(false);
      expect(ctrl.blockableUnknown).toBe(true);
    });

    it('if the package content retrieval fails', () => {
      setBlockable(defaultSantaBundle);
      setPackageContents(null);

      ctrl = buildController();
      scope.$apply();

      expect(errorService.createToastFromError).toHaveBeenCalled();
    });

    it('if the recent event context retrieval fails', () => {
      setPendingState(null);

      ctrl = buildController();
      scope.$apply();

      expect(errorService.createToastFromError).toHaveBeenCalled();
    });

    it('if the recent event context retrieval fails', () => {
      setRecentEvent(null);

      ctrl = buildController();
      scope.$apply();

      expect(errorService.createToastFromError).toHaveBeenCalled();
    });

    it('if the user retrieval fails', () => {
      setBlockable({'id': 'abcd'});
      userResource['getSelf']['and']['callFake'](() => {
        return {'$promise': q.reject('foo')};
      });

      ctrl = buildController();
      scope.$apply();

      expect(errorService.createDialogFromError).toHaveBeenCalled();
    });

    it('if the vote cast fails', () => {
      setBlockable({'id': 'abcd'});
      setUser({});

      ctrl = buildController();
      scope.$apply();

      setYesVoteCast(null, null);

      ctrl.request();
      scope.$apply();

      expect(errorService.createDialogFromError).toHaveBeenCalled();
      expect(ctrl.localVoteCast).toBe(false);
    });

    it('if the vote cast fails with a 409', () => {
      setBlockable({'id': 'abcd'});
      setUser({});

      ctrl = buildController();
      scope.$apply();

      voteCastResource['voteYes']['and']['returnValue'](
          {'$promise': q.reject({'status': 409})});

      ctrl.request();
      scope.$apply();

      expect(errorService.createSimpleToast).toHaveBeenCalled();
      expect(ctrl.localVoteCast).toBe(false);
    });
  });

  describe('upon success', () => {
    describe('should require viewing all vote steps', () => {
      it('when the user has never voted', () => {
        setUser({'isAdmin': false, 'roles': ['USER'], 'lastVoteDt': null});
        setVote(null);

        ctrl = buildController();
        scope.$apply();

        expect(getStepper().currentStep).toEqual(0);
      });

      it('when the user has not voted in over 60 days', () => {
        let ninetyDaysAgo = new Date().getTime() -
            1.5 * BlockableDetailsCtrl.MAX_TIME_SINCE_LAST_VOTE;
        setUser({
          'isAdmin': false,
          'roles': ['USER'],
          'lastVoteDt': new Date(ninetyDaysAgo).toISOString()
        });
        setVote(null);

        ctrl = buildController();
        scope.$apply();

        expect(getStepper().currentStep).toEqual(0);
      });
    });

    describe('should not require viewing all vote steps', () => {
      let buildCtrlAndTest_ = () => {
        ctrl = buildController();
        scope.$apply();

        expect(ctrl.isVotingAllowed()).toBe(true);
        expect(getStepper().currentStep).toEqual(2);
      };

      beforeEach(() => {
        setVote(null);
      });

      it('when the user is an admin', () => {
        setUser({'isAdmin': true, 'roles': ['USER']});

        buildCtrlAndTest_();
      });

      it('when the user is a superuser', () => {
        setUser({'isAdmin': false, 'roles': ['SUPERUSER']});

        buildCtrlAndTest_();
      });

      it('when the user has voted recently', () => {
        let thirtyDaysAgo = new Date().getTime() -
            .5 * BlockableDetailsCtrl.MAX_TIME_SINCE_LAST_VOTE;
        setUser({
          'isAdmin': false,
          'roles': ['USER'],
          'lastVoteDt': new Date(thirtyDaysAgo).toISOString(),
        });

        buildCtrlAndTest_();
      });
    });

    describe('should unconditionally skip to later steps', () => {
      it('when the user has already voted', () => {
        setUser({'isAdmin': false, 'roles': ['USER']});

        ctrl = buildController();
        scope.$apply();

        expect(getStepper().currentStep).toEqual(3);
      });

      it('when the user is not allowed to vote', () => {
        setVote(null);
        setUser({'isAdmin': false, 'roles': ['USER']});
        setBlockable({'id': 'abcd', 'isVotingAllowed': false});

        ctrl = buildController();
        scope.$apply();

        expect(ctrl.isVotingAllowed()).toBe(false);
        expect(getStepper().currentStep).toEqual(2);
      });
    });

    describe('should receive a vote', () => {
      beforeEach(() => {
        routeParams['id'] = 'abcd';

        ctrl = buildController();

        setBlockable({'id': 'abcd'});
      });

      it('on load', () => {
        expect(ctrl.hasCastVote()).not.toBe(true);
        expect(ctrl.wasYesVote()).not.toBe(true);

        scope.$apply();

        expect(voteCastResource['get']).toHaveBeenCalledWith({'id': 'abcd'});
        expect(ctrl.hasCastVote()).toBe(true);
        expect(ctrl.wasYesVote()).toBe(true);
      });
    });

    describe('should set the isBit9 flag', () => {
      beforeEach(() => {
        routeParams['id'] = 'abcd';
      });

      it('if the blockable is from Santa', () => {
        setBlockable({'class_': ['Blockable', 'Binary', 'SantaBinary']});

        ctrl = buildController();
        scope.$apply();

        expect(ctrl.isBit9).not.toBe(true);
      });

      it('if the blockable is from Bit9', () => {
        setBit9Blockable({});

        ctrl = buildController();
        scope.$apply();

        expect(ctrl.isBit9).toBe(true);
      });
    });

    describe('should cast a vote', () => {
      beforeEach(() => {
        setUser({'isAdmin': true});
        setVote(null);
        routeParams['id'] = 'abcd';

        ctrl = buildController();
        scope.$apply();

        expect(ctrl.hasCastVote()).not.toBe(true);
        expect(ctrl.wasYesVote()).not.toBe(true);
      });

      it('of yes', () => {
        ctrl.request();
        scope.$apply();

        expect(voteCastResource['voteYes']['calls'].count()).toEqual(1);
        expect(voteCastResource['voteYes']['calls']['argsFor'](0)).toEqual([
          {'id': 'abcd', 'asRole': UserRole['USER']}
        ]);
        expect(ctrl.hasCastVote()).toBe(true);
        expect(ctrl.wasYesVote()).toBe(true);
      });

      it('of no', () => {
        ctrl.flag();
        scope.$apply();

        expect(voteCastResource['voteNo']['calls'].count()).toEqual(1);
        expect(voteCastResource['voteNo']['calls']['argsFor'](0)).toEqual([
          {'id': 'abcd', 'asRole': UserRole['USER']}
        ]);

        expect(ctrl.hasCastVote()).toBe(true);
        expect(ctrl.wasYesVote()).not.toBe(true);
      });

      it('and update the pending state', () => {
        expect(ctrl.vote).toEqual(null);
        expect(ctrl.isPending).toBe(false);

        setPendingState(true);

        ctrl.request();
        scope.$apply();

        expect(ctrl.isPending).toBe(true);
        expect(ctrl.hasCastVote()).toBe(true);
      });

      it('and advance to the next step', () => {
        expect(getStepper().currentStep).not.toEqual(3);
        expect(ctrl.vote).toEqual(null);

        ctrl.request();
        scope.$apply();

        expect(getStepper().currentStep).toEqual(3);

        expect(ctrl.hasCastVote()).toBe(true);
      });
    });

    describe('should not cast a vote', () => {
      it('if there is no id property on the blockable', () => {
        routeParams['id'] = 'abcd';
        setBlockable({'id': null});

        ctrl = buildController();
        scope.$apply();

        ctrl.flag();
        scope.$apply();

        expect(voteCastResource['voteYes']['calls'].count()).toEqual(0);
        expect(voteCastResource['voteNo']['calls'].count()).toEqual(0);
      });
    });

    it('should properly transition between localVoteCast and wasYesVote ' +
           'states during voting.',
       () => {
         setVote(null);

         ctrl = buildController();
         scope.$apply();

         expect(ctrl.hasCastVote()).toBe(false);
         expect(ctrl.localVoteCast).toBe(false);

         ctrl.flag();

         expect(ctrl.hasCastVote()).toBe(false);
         expect(ctrl.localVoteCast).toBe(true);
         expect(ctrl.wasYesVote()).toBe(false);

         scope.$apply();

         expect(ctrl.hasCastVote()).toBe(true);
         expect(ctrl.localVoteCast).toBe(false);
         expect(ctrl.wasYesVote()).toBe(false);

         ctrl.request();

         // hasCastVote will be true from the previous vote.
         expect(ctrl.hasCastVote()).toBe(true);
         expect(ctrl.localVoteCast).toBe(true);
         expect(ctrl.wasYesVote()).toBe(true);

         scope.$apply();

         expect(ctrl.hasCastVote()).toBe(true);
         expect(ctrl.localVoteCast).toBe(false);
         expect(ctrl.wasYesVote()).toBe(true);
       });


    describe('should properly toggle between installer states', () => {
      beforeEach(() => {
        setBit9Blockable({'isInstaller': true, 'detectedInstaller': true});
        setInstallerPendingState(false);

        ctrl = buildController();
        scope.$apply();
      });

      it('', () => {
        setInstallerPendingState(true);
        setSetInstallerForce(false);

        ctrl.toggleInstallerForce();
        scope.$apply();
        scope.$apply();

        expect(ctrl.isInstaller).toBe(false);
        expect(ctrl.isInstallerPending).toBe(true);
      });

      it('or abort when a request fails', () => {
        setInstallerPendingState(null);
        setSetInstallerForce(false);

        ctrl.toggleInstallerForce();
        scope.$apply();
        scope.$apply();

        // Ensure the installer state is unchanged.
        expect(ctrl.isInstaller).toBe(true);
        expect(ctrl.isInstallerPending).toBe(false);
      });

      it('and show a dialog if changing the default', () => {
        setInstallerPendingState(true);
        setSetInstallerForce(false);

        ctrl.requestInstallerToggle();
        scope.$apply();
        scope.$apply();

        expect(mdDialog['show']['calls'].count()).toEqual(1);
        expect(ctrl.isInstaller).toBe(false);
        expect(ctrl.isInstallerPending).toBe(true);
      });

      it('and show no dialog if not changing the default', () => {
        ctrl['blockable']['detectedInstaller'] = false;

        setInstallerPendingState(true);
        setSetInstallerForce(false);

        ctrl.requestInstallerToggle();
        scope.$apply();
        scope.$apply();

        expect(mdDialog['show']['calls'].count()).toEqual(0);
        expect(ctrl.isInstaller).toBe(false);
        expect(ctrl.isInstallerPending).toBe(true);
      });
    });

    describe('should initialize', () => {
      it('voting weights', () => {
        setUser({'isAdmin': true});

        ctrl = buildController();
        scope.$apply();

        expect(ctrl.userHasElevatedPermissions()).toBe(true);
        expect(settingResource['get']).toHaveBeenCalledWith({
          'setting': 'votingWeights'
        });

        expect(ctrl.votingWeights).toContain({'role': 'USER', 'weight': 1});
      });

      it('package contents', () => {
        let bundleBinary = {'id': 'abcd', 'certId': 'ffff'};
        setBlockable(defaultSantaBundle);
        setPackageContents([bundleBinary]);

        ctrl = buildController();
        scope.$apply();

        expect(ctrl.contents).toEqual([bundleBinary]);
      });

      describe('blockable pending state', () => {
        it('', () => {
          setPendingState(true);

          ctrl = buildController();
          scope.$apply();

          expect(ctrl.isPending).toBe(true);
        });
        it('and if true set an timeout function to periodically check', () => {
          setPendingState(true);

          ctrl = buildController();
          scope.$apply();

          expect(ctrl.isPending).toBe(true);

          timeout.flush(10001);
          expect(ctrl.isPending).toBe(true);

          setPendingState(false);
          timeout.flush(10001);
          expect(ctrl.isPending).toBe(false);
        });
      });

      it('installer (and pending) state', () => {
        setBit9Blockable({'isInstaller': true});
        setInstallerPendingState(true);

        ctrl = buildController();
        scope.$apply();

        expect(ctrl.isInstaller).toBe(true);
        expect(ctrl.isInstallerPending).toBe(true);
      });
    });
  });

  describe('should disable the flag button', () => {
    it('if the blockable is a bundle', () => {
      let bundleBinary = {'id': 'abcd', 'certId': 'ffff'};
      setBlockable(defaultSantaBundle);
      setPackageContents([bundleBinary]);

      ctrl = buildController();
      scope.$apply();

      expect(ctrl.disableFlagButton()).toBe(true);
    });
  });

  describe('should enable the flag button', () => {
    it('if the blockable is a non-bundle SantaBlockable', () => {
      setBlockable({'class_': ['Blockable', 'Binary', 'SantaBlockable']});

      ctrl = buildController();
      scope.$apply();

      expect(ctrl.disableFlagButton()).toBe(false);
    });
    it('if the blockable is a Bit9Binary', () => {
      setBlockable({'class_': ['Blockable', 'Binary', 'Bit9Binary']});

      ctrl = buildController();
      scope.$apply();

      expect(ctrl.disableFlagButton()).toBe(false);
    });
  });

});
});  // goog.scope
