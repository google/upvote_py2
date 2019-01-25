# Copyright 2017 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Email-related utility functions."""

import logging

from google.appengine.api import mail
from upvote.gae import settings
from upvote.gae.utils import user_utils


_SENDER = 'Upvote <upvote@%s>' % settings.USER_EMAIL_DOMAIN
_SUBJECT_PREFIX = '[Upvote]'
_REPLY_TO = 'upvote@%s' % settings.USER_EMAIL_DOMAIN


class Error(Exception):
  """Base error class for this module."""


class NoRecipientsError(Error):
  """Raised if no mail recipients are specified."""


def _SanitizeAddrs(addrs):
  if isinstance(addrs, list):
    return [user_utils.UsernameToEmail(addr.strip()) for addr in addrs]
  elif isinstance(addrs, str):
    return [user_utils.UsernameToEmail(addrs.strip())]
  else:
    return []


def Send(subject, body, to=None, cc=None, bcc=None, html=False):
  """Sends an email.

  Args:
    subject: The email subject.
    body: The email body.
    to: The TO address(es). Can be either a string or list of strings, and each
        string can be either a username or email address.
    cc: The CC address(es). Can be either a string or list of strings, and each
        string can be either a username or email address.
    bcc: The BCC address(es). Can be either a string or list of strings, and
        each string can be either a username or email address.
    html: Whether the body contains HTML or plain text.

  Raises:
    NoRecipientsError: if the to, cc, and bcc arguments are all empty.
  """
  message = mail.EmailMessage(
      sender=_SENDER,
      reply_to=_REPLY_TO,
      subject='%s %s' % (_SUBJECT_PREFIX, subject))

  if html:
    message.html = body
  else:
    message.body = body

  to = _SanitizeAddrs(to)
  cc = _SanitizeAddrs(cc)
  bcc = _SanitizeAddrs(bcc)

  if to:
    message.to = to
  if cc:
    message.cc = cc
  if bcc:
    message.bcc = bcc

  # Make sure we're actually sending this to someone.
  recipients = sorted(list(set(to + cc + bcc)))
  if not recipients:
    raise NoRecipientsError

  try:
    logging.info('Sending email to %s', recipients)
    message.check_initialized()
    message.send()

  # If something blows up, log it and move on. Failure to send an email is not
  # something that should take the caller off the rails.
  except Exception:  # pylint: disable=broad-except
    logging.exception('Error encountered while sending email')
