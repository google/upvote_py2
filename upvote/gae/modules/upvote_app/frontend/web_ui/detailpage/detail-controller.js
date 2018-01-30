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

goog.provide('upvote.detailpage.BlockableDetailsController');

goog.require('upvote.admin.app.constants');
goog.require('upvote.blockables.BlockableService');
goog.require('upvote.shared.constants.BlockableState');
goog.require('upvote.shared.constants.UiBlockableState');
goog.require('upvote.shared.constants.UserRole');
goog.require('upvote.shared.models.AnyBlockable');
goog.require('upvote.shared.models.User');
goog.require('upvote.shared.models.Vote');
goog.require('upvote.statechip.ToUiState');

goog.scope(() => {
const BlockableState = upvote.shared.constants.BlockableState;
const UiState = upvote.shared.constants.UiBlockableState;
const UserRole = upvote.shared.constants.UserRole;


/**
 * There is no externs for this.
 *
 * @typedef {{
 *   get: function(string): ?Object,
 *   register: function(?Object, string): function(): void,
 *   when: function(string): !angular.$q.Promise,
 *   notFoundError: function(string): void
 * }}
 */
let ComponentRegistry;


/** Controller for individual blockable detail. */
upvote.detailpage.BlockableDetailsController = class {
  /**
   * @param {!angular.Resource} blockableResource
   * @param {!upvote.blockables.BlockableService} blockableService
   * @param {!angular.Resource} recentEventResource
   * @param {!angular.Resource} userResource
   * @param {!angular.Resource} voteCastResource
   * @param {!angular.Resource} settingResource
   * @param {!upvote.errornotifier.ErrorService} errorService
   * @param {!angular.$q} $q
   * @param {!angular.$routeParams} $routeParams
   * @param {!angular.$timeout} $timeout
   * @param {!angular.Scope} $scope
   * @param {!md.$dialog} $mdDialog
   * @param {!ComponentRegistry} $mdComponentRegistry
   * @param {!Object} page
   * @ngInject
   */
  constructor(
      blockableResource, blockableService, recentEventResource, userResource,
      voteCastResource, settingResource, errorService, $q, $routeParams,
      $timeout, $scope, $mdDialog, $mdComponentRegistry, page) {
    /** @private {!angular.Resource} */
    this.blockableResource_ = blockableResource;
    /** @private {!upvote.blockables.BlockableService} */
    this.blockableService_ = blockableService;
    /** @private {!angular.Resource} */
    this.recentEventResource_ = recentEventResource;
    /** @private {!angular.Resource} */
    this.userResource_ = userResource;
    /** @private {!angular.Resource} */
    this.voteCastResource_ = voteCastResource;
    /** @private {!angular.Resource} */
    this.settingResource_ = settingResource;
    /** @private {!upvote.errornotifier.ErrorService} errorService */
    this.errorService_ = errorService;
    /** @private {!angular.$q} */
    this.q_ = $q;
    /** @private {!angular.$routeParams} */
    this.routeParams_ = $routeParams;
    /** @private {!angular.$timeout} */
    this.timeout_ = $timeout;
    /** @private {!angular.Scope} */
    this.scope_ = $scope;
    /** @private {!md.$dialog} */
    this.mdDialog_ = $mdDialog;
    /** @private {!ComponentRegistry} */
    this.mdComponentRegistry_ = $mdComponentRegistry;

    /** @export {string} */
    this.id = '';
    /** @export {?upvote.shared.models.AnyBlockable} */
    this.blockable = null;
    /** @export {?upvote.events.AnyEventWithContext} */
    this.recentEventCtx = null;
    /** @export {?upvote.shared.models.User} */
    this.user = null;
    /** @export {boolean} */
    this.expandHash = false;

    /** @export {boolean} */
    this.isBit9 = false;
    /** @export {boolean} */
    this.isPending = false;
    /** @private {?angular.$q.Promise} */
    this.timeoutPromise_ = null;
    /** @export {boolean} */
    this.isInstaller = false;
    /** @export {boolean} */
    this.isInstallerPending = false;

    /** @export {?upvote.shared.models.SantaCertificate} */
    this.cert = null;
    /** @export {!Array<!upvote.shared.models.SantaBundleBinary>} */
    this.contents = [];
    /** @export {?upvote.shared.models.Vote} */
    this.vote = null;
    /** @export {?Object<string, Object<string, number>>} */
    this.votingThresholds = null;
    /** @export {!Array<{'role': string, 'weight': number}>} */
    this.votingWeights = [];
    /** @export {?upvote.shared.constants.UserRole} */
    this.requestedVoteRole = UserRole['USER'];

    /** @export {?upvote.shared.constants.UiBlockableState} */
    this.lastUiState = null;

    // These two properties allow the UI to responsively update button
    // visibility and display text (i.e. not have wait for a server response).
    /** @export {boolean} */
    this.localVoteCast = false;
    /** @private {?boolean} */
    this.localWasYesVote_ = null;

    /** @private {?angular.$q.Promise} */
    this.stepperLoadedPromise_ = null;

    page.title = 'Applications';

    this.init_();
  }

  /** @private */
  init_() {
    this.id = this.routeParams_['id'];

    // This promise will synchronize the loading of the stepper with the
    // step-advancing operations which must take place after its
    // initialization.
    this.stepperLoadedPromise_ =
        this.mdComponentRegistry_.when(BlockableDetailsCtrl.STEPPER_ID_);

    this.recentEventResource_
        .get({'id': this.id, 'withContext': true})['$promise']
        .then((event_) => {
          this.recentEventCtx = event_;
        })
        .catch((response) => {
          this.errorService_.createToastFromError(response);
        });

    this.refreshPending_();

    this.blockableService_.getInstallerPending(this.id)
        .then((result) => {
          this.isInstallerPending = result['data'];
        })
        .catch((response) => {
          this.errorService_.createToastFromError(response);
        });

    this.blockableResource_.get({'id': this.id})['$promise']
        .then((blockable) => {
          this.blockable = blockable;
          // NOTE: Even empty Angular Resource response objects will
          // be truthy as they'll have '$promise' and '$resolved' properties.
          if (!this.blockable['id']) {
            return;
          }

          this.isBit9 = this.blockable['class_']
                            .map((val) => val.startsWith('Bit9'))
                            .reduce((acc, val) => acc || val, false);
          this.isInstaller = this.blockable['isInstaller'];

          if (!!this.blockable['certId']) {
            this.blockableResource_
                .get({'id': this.blockable['certId']})['$promise']
                .then((cert) => {
                  this.cert = cert;
                })
                .catch((response) => {
                  this.errorService_.createToastFromError(response);
                });
          }

          if (!!this.isPackage()) {
            this.blockableService_.getPackageContents(this.blockable['id'])
                .then((result) => {
                  this.contents = result['data'];
                })
                .catch((response) => {
                  this.errorService_.createToastFromError(response);
                });
          }
          // Wait for stepper to be loaded before skipping any steps.
          this.stepperLoadedPromise_.then(() => {
            // If user is not allowed to vote, only skip to the voting step.
            if (!this.isVotingAllowed()) {
              this.completeUntil_(BlockableDetailsCtrl.VOTING_STEP_IDX_);
            }
          });
          return this.voteCastResource_.get(
              {'id': blockable['id']})['$promise'];
        })
        .then((vote) => {
          this.vote = vote;

          // Wait for stepper to be loaded before skipping any steps.
          this.stepperLoadedPromise_.then(() => {
            // If the user has already voted on this blockable, skip to the last
            // step.
            if (this.hasCastVote()) {
              let lastStep = BlockableDetailsCtrl.VOTING_STEP_IDX_ + 1;
              this.completeUntil_(lastStep);
            }
          });
        })
        .catch((response) => {
          this.errorService_.createToastFromError(response);
        });

    // Determine whether the user needs to be put through each voting step.
    this.userResource_['getSelf']()['$promise']
        .then((user) => {
          this.user = user;
          this.initStepperState_();

          if (this.userHasElevatedPermissions()) {
            return this.settingResource_.get(
                {'setting': 'votingWeights'})['$promise'];
          }
          return this.q_.resolve();
        })
        .then((results) => {
          // If the settings call was made, we'll have a result here.
          if (results) {
            for (let role of Object.keys(results)) {
              // The '$resolved' property is also returned in the response.
              if (typeof results[role] != 'number') {
                continue;
              }
              this.votingWeights.push({'role': role, 'weight': results[role]});
            }
          }
        })
        .catch((response) => {
          this.errorService_.createDialogFromError(response);
        });

    this.settingResource_.get({'setting': 'votingThresholds'})['$promise']
        .then((results) => {
          this.votingThresholds = results;
        })
        .catch((response) => {
          this.errorService_.createToastFromError(response);
        });

    // Terminate the pending refresh cycle when the scope is torn down.
    this.scope_.$on('$destroy', () => {
      if (this.timeoutPromise_ !== null) {
        this.timeout_.cancel(this.timeoutPromise_);
      }
    });
  }

  /**
   * Refresh the blockable pending state.
   *
   * Also sets an timeout function to periodically refresh the pending state
   * until the pending state returns false.
   *
   * @private
   */
  refreshPending_() {
    this.blockableService_.getPending(this.id)
        .then((result) => {
          this.isPending = result['data'];
        })
        .catch((response) => {
          this.errorService_.createToastFromError(response);
        })
        .then(() => {
          if (this.isPending && this.timeoutPromise_ === null) {
            this.timeoutPromise_ = this.timeout_(() => {
              this.timeoutPromise_ = null;
              this.refreshPending_();
            }, 10000);  // Refresh every 10 seconds.
          }
        });
  }

  /**
   * Advance the stepper to the provided step.
   * @param {number} step
   * @private
   */
  completeUntil_(step) {
    // NOTE: stepper.goto() is not used here because this method may
    // be called prior to the steps being linked to the stepper. In this case,
    // goto() would be a no-op because it prevents moving to an invalid step.
    let stepper =
        this.mdComponentRegistry_.get(BlockableDetailsCtrl.STEPPER_ID_);
    stepper.currentStep = step;
  }

  /**
   * Advance the stepper to the next step.
   * @export
   */
  next() {
    let stepper =
        this.mdComponentRegistry_.get(BlockableDetailsCtrl.STEPPER_ID_);
    stepper.next();
  }

  /**
   * Returns whether the stepper is on the provided step.
   * @param {number} step
   * @return {boolean}
   * @export
   */
  isCurrentStep(step) {
    let stepper =
        this.mdComponentRegistry_.get(BlockableDetailsCtrl.STEPPER_ID_);
    return stepper.currentStep === step;
  }

  /**
   * Initialize the stepper state using the user's roles and voting history.
   * @private
   */
  initStepperState_() {
    let requireSteps;
    let lastVoteTime = new Date(this.user['lastVoteDt']).getTime();
    let currentTime = new Date().getTime();

    if (this.user['isAdmin'] || this.user['roles'].includes('SUPERUSER')) {
      requireSteps = false;
    } else if (!lastVoteTime) {
      // If the user has never voted, require them to go through the steps.
      requireSteps = true;
    } else {
      let timeSinceLastVote = currentTime - lastVoteTime;

      // If more than MAX_TIME_SINCE_LAST_VOTE has passed since the user last
      // cast a vote, force them to go through the voting steps again.
      requireSteps =
          timeSinceLastVote > BlockableDetailsCtrl.MAX_TIME_SINCE_LAST_VOTE;
    }

    this.stepperLoadedPromise_.then(() => {
      if (!requireSteps) {
        this.completeUntil_(BlockableDetailsCtrl.VOTING_STEP_IDX_);
      }
    });
  }

  /**
   * Return the current UiBlockableState.
   * @return {?upvote.shared.constants.UiBlockableState}
   * @export
   */
  getUiState() {
    return upvote.statechip.ToUiState(
        this.blockable['state'], this.vote, this.cert);
  }

  /**
   * Request that the installer state of the blockable be toggled.
   * @export
   */
  requestInstallerToggle() {
    if (!this.isBit9) {
      return;
    }
    if (this.isInstaller == this.blockable['detectedInstaller']) {
      let dialog =
          this.mdDialog_.confirm()
              .title('Change \'Application Role\' away from the default?')
              .htmlContent(
                  'Our system usually defaults to the correct Application Role.')
              .ok('Yes, Make the change!')
              .cancel('Cancel');
      this.mdDialog_.show(dialog).then(() => this.toggleInstallerForce());
    } else {
      this.toggleInstallerForce();
    }
  }

  /**
   * Toggle the installer state of the blockable.
   * @export
   */
  toggleInstallerForce() {
    if (!this.isBit9) {
      return;
    }
    this.blockableService_.setInstallerForce(this.id, !this.isInstaller)
        .then((setResult) => {
          this.blockableService_.getInstallerPending(this.id)
              .then((pendingResult) => {
                // Wait until both requests complete to update the UI.
                this.isInstaller = setResult['data'];
                this.isInstallerPending = pendingResult['data'];
              })
              .catch((response) => {
                this.errorService_.createToastFromError(response);
              });
        })
        .catch((response) => {
          this.errorService_.createToastFromError(response);
        });
  }

  /**
   * Return whether the user has cast a vote on the current blockable.
   * @return {boolean}
   * @export
   */
  hasCastVote() {
    return !!this.vote && !!this.vote['id'];
  }

  /**
   * Return whether the user cast an upvote on the current blockable.
   * If the user has not cast a vote, false is returned.
   * @return {boolean}
   * @export
   */
  wasYesVote() {
    if (this.localVoteCast) {
      return !!this.localWasYesVote_;
    } else {
      return !!this.vote && !!this.vote['wasYesVote'];
    }
  }

  /**
   * Return whether the user is allowed to vote on the current Blockable.
   * @return {boolean}
   * @export
   */
  isVotingAllowed() {
    return !!this.blockable && !!this.blockable['isVotingAllowed'];
  }

  /**
   * Return whether the current blockable is a Package.
   * @return {boolean}
   * @export
   */
  isPackage() {
    return !!this.blockable && this.blockable['class_'].includes('Package');
  }

  /**
   * Return whether the user has an event associated with the current Blockable.
   * @return {boolean}
   * @export
   */
  hasRecentEvent() {
    return !!this.recentEventCtx && !!this.recentEventCtx['event'];
  }

  /**
   * Indicates whether the request button should be disabled.
   * @return {boolean}
   * @export
   */
  disableRequestButton() {
    return this.localVoteCast || (this.hasCastVote() && this.wasYesVote()) ||
        !this.isVotingAllowed();
  }

  /**
   * Indicates whether the flag button should be disabled.
   * @return {boolean}
   * @export
   */
  disableFlagButton() {
    return this.localVoteCast || (this.hasCastVote() && !this.wasYesVote()) ||
        !this.isVotingAllowed() || !!this.contents;
  }

  /**
   * Register an upvote for current blockable.
   * @export
   */
  request() {
    this.castVote_(true);
  }

  /**
   * Register a downvote for current blockable.
   * @export
   */
  flag() {
    this.castVote_(false);
  }

  /**
   * Register a vote for current blockable.
   * @private
   */
  castVote_(isUpVote) {
    this.localVoteCast = true;
    this.localWasYesVote_ = isUpVote;
    if (!this.blockable || !this.blockable['id']) {
      return;
    }
    let castFunction = isUpVote ? this.voteCastResource_['voteYes'] :
                                  this.voteCastResource_['voteNo'];
    castFunction({'id': this.id, 'asRole': this.requestedVoteRole})['$promise']
        .then((response) => {
          this.blockable = response['blockable'];
          this.vote = response['vote'];

          this.refreshPending_();

          // Advance stepper so post-voting step is shown.
          this.completeUntil_(BlockableDetailsCtrl.VOTING_STEP_IDX_ + 1);
        })
        .catch((response) => {
          if (!!response && response['status'] == 409) {
            this.errorService_.createSimpleToast(
                'You\'ve already voted on this application.');
          } else {
            this.errorService_.createDialogFromError(response);
          }
        })
        .finally(() => {
          // Unset local values to reflect the actual voting state.
          this.localVoteCast = false;
          this.localWasYesVote_ = null;
        });
  }

  /**
   * Return the number of votes needed to change the state of the blockable.
   * @return {number}
   * @export
   */
  votesToGo() {
    switch (this.getUiState()) {
      case UiState['GLOBALLY_WHITELISTED']:
      case UiState['CERT_WHITELISTED']:
      case UiState['WHITELISTED']:
        return 0;
      case UiState['AVAILABLE']:
        return 1;
      case UiState['AWAITING_VOTES']:
        return this.votingThresholds
                   [BlockableState['APPROVED_FOR_LOCAL_WHITELISTING']] -
            this.blockable['score'];
      case UiState['CERT_BANNED']:
      case UiState['FLAGGED']:
      case UiState['BANNED']:
      default:
        return -1;
    }
  }

  /**
   * Indicates if the current user has more permissions than a normal user.
   * @return {boolean}
   * @export
   */
  userHasElevatedPermissions() {
    return !!this.user &&
        (this.user['roles'].includes(UserRole['TRUSTED_USER']) ||
         this.user['roles'].includes(UserRole['SUPERUSER']) ||
         this.user['isAdmin']);
  }

  getAdminUrl() {
    return upvote.admin.app.constants.URL_PREFIX + 'blockables/' + this.id;
  }
};
let BlockableDetailsCtrl = upvote.detailpage.BlockableDetailsController;

/** @private {string} */
BlockableDetailsCtrl.STEPPER_ID_ = 'voting-stepper';
/** @private {number} */
BlockableDetailsCtrl.NUM_VOTING_STEPS_ = 4;
/** @private {number} */
BlockableDetailsCtrl.VOTING_STEP_IDX_ = 2;

/**
 * The maximum time since the user last cast a vote before they are forced to
 * go through the voting steps again. The current limit is 60 days.
 * @export {number}
 */
BlockableDetailsCtrl.MAX_TIME_SINCE_LAST_VOTE = (1000 * 60 * 60 * 24) * 60;
});  // goog.scope
