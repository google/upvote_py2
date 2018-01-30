#!/usr/bin/python
"""Command-line tool for enabling and disabling sections of cron jobs."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import argparse
import collections
import os
import re
import sys


class Commenter(object):
  """Utility for commenting, un-commenting, and viewing a file by sections.

  Sections are delimitted by BEGIN and END tags both containing the name of the
  section. The default format is the default value of the "delimter_regex"
  param.

  Comments are detected, added, and removed according to the value passed to the
  "comment_prefix" param.
  """

  def __init__(
      self, file_text=None, comment_prefix='#~~~ ',
      delimiter_regex=r'####\s*(BEGIN|END):\s*(\w+)\s*####'):
    self._lines = file_text and file_text.splitlines()
    self._prefix = comment_prefix
    self._delimiter_regex = re.compile(delimiter_regex)

  def _iter_with_section(self):
    """Return an iterator over a 2-tuple of (annotated section, file line).

    Yields:
      (section_name, line):
        section_name: str or None, The name of section if "line" is *inside* of
          two tags. Otherwise, None.
        line: str, The string contents of the line.
    """
    section = None
    for line_no, line in enumerate(self._lines):
      control_line = self._delimiter_regex.match(line)
      if control_line is not None:
        type_, new_section = control_line.groups()
        if type_ == 'END':
          assert section is not None, (
              'Line %d: Got unexpected END tag' % (line_no))
          assert new_section == section, (
              'Line %d: Mismatched END tag: got "%s", expected "%s"' % (
                  line_no, new_section, section))
          section = None
        elif type_ == 'BEGIN':
          section = new_section
        yield (None, line)
      else:
        yield (section, line)
    assert section is None, 'Unmatched BEGIN statement: "%s"' % section

  def _is_commented(self, line):
    return line.startswith(self._prefix)

  def _enable_line(self, line):
    if self._is_commented(line):
      return line[len(self._prefix):]
    else:
      return line

  def _disable_line(self, line):
    if not self._is_commented(line):
      return self._prefix + line
    else:
      return line

  def set_text(self, file_text):
    self._lines = file_text.splitlines()

  def get_section_names(self):
    dict_ = collections.OrderedDict()
    for section, _ in self._iter_with_section():
      dict_.setdefault(section, '')
    del dict_[None]
    return dict_.keys()

  def enable(self, args):
    assert args.section in self.get_section_names(), (
        'Unknown section name: %s' % args.section)
    return '\n'.join(
        self._enable_line(line) if line_section == args.section else line
        for line_section, line in self._iter_with_section())

  def disable(self, args):
    assert args.section in self.get_section_names(), (
        'Unknown section name: %s' % args.section)
    return '\n'.join(
        self._disable_line(line) if line_section == args.section else line
        for line_section, line in self._iter_with_section())

  def enable_all(self, unused_args):
    return '\n'.join(
        self._enable_line(line) if line_section is not None else line
        for line_section, line in self._iter_with_section())

  def disable_all(self, unused_args):
    return '\n'.join(
        self._disable_line(line) if line_section is not None else line
        for line_section, line in self._iter_with_section())

  def print_status(self, unused_args):
    """Prints the status of each section in the file."""
    statuses = collections.OrderedDict()
    for section, line in self._iter_with_section():
      if section is None:
        continue
      elif section not in statuses:
        statuses[section] = ''
      elif not statuses[section]:
        statuses[section] = (
            'DISABLED' if self._is_commented(line) else 'ENABLED')
      elif (statuses[section] == 'ENABLED' and self._is_commented(line) or
            statuses[section] == 'DISABLED' and not self._is_commented(line)):
        statuses[section] = 'PARTIAL'
    print('##  Section Statuses  ##')
    max_pad = max(len(name) for name in statuses.keys())
    for section_name, status in statuses.iteritems():
      print('  {}: {}{}'.format(
          section_name, ' ' * (max_pad - len(section_name)), status))


def main(unused_argv):
  default_cron_path = os.path.join(
      os.path.abspath('.'), 'upvote', 'gae', 'cron.yaml')
  commenter = Commenter()

  parser = argparse.ArgumentParser(
      description='Enable/disable sections of cron jobs.')
  parser.add_argument(
      '--cron_file', default=default_cron_path,
      help='The path to the cron file to be managed')
  subparsers = parser.add_subparsers()

  # Group modifications.
  for action in ('enable', 'disable'):
    subparser = subparsers.add_parser(
        action, help='%s a section' % action.capitalize())
    subparser.add_argument(
        'section',
        help='The section to be %sd' % action)
    subparser.set_defaults(func=getattr(commenter, action))

  # Bulk modifications.
  for action in ('enable_all', 'disable_all'):
    subparser = subparsers.add_parser(
        action, help='%s all sections' % action.split('_')[0].capitalize())
    subparser.set_defaults(func=getattr(commenter, action))

  # Get status of sections.
  subparser = subparsers.add_parser('status', help='Print section status')
  subparser.set_defaults(func=commenter.print_status)

  # Parse and run the prescribed operation.
  args = parser.parse_args()
  with open(args.cron_file, 'r') as f:
    commenter.set_text(f.read())

  # Run the function.
  try:
    output = args.func(args)
  except AssertionError as e:
    print('(ERROR)', e.message)
  else:
    if output is not None:
      with open(args.cron_file, 'w') as f:
        f.write(output)
        f.write('\n')


if __name__ == '__main__':
  main(sys.argv)
