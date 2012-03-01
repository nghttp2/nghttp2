#!/usr/bin/env python
"""End to end tests for the example programs.

This test assumes the examples have already been built.

At the moment top_buiddir is not in the environment, but top_builddir would be
more reliable than '..', so it's worth trying to pull it from the environment.
"""

__author__ = 'Jim Morrison <jim@twist.com>'


import os
import subprocess
import sys
import time
import unittest


_PORT = 9893


def _run_server(port, args):
  srcdir = os.environ.get('srcdir', '.')
  testdata = '%s/testdata' % srcdir
  top_builddir = os.environ.get('top_builddir', '..')
  base_args = ['%s/examples/spdyd' % top_builddir, str(port), '-d', testdata,
               '%s/privkey.pem' % testdata, '%s/cacert.pem' % testdata]
  if args:
    base_args.extend(args)
  return subprocess.Popen(base_args)

def _check_server_up(port):
  # Check this check for now.
  time.sleep(1)

def _kill_server(server):
  while server.returncode is None:
    server.terminate()
    time.sleep(1)
    server.poll()


class EndToEndSpdyTests(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.server = _run_server(_PORT, None)
    _check_server_up(_PORT)

  @classmethod
  def tearDownClass(cls):
    _kill_server(cls.server)

  def setUp(self):
    build_dir = os.environ.get('top_builddir', '..')
    self.client = '%s/examples/spdycat' % build_dir

  def testSimpleRequest(self):
    self.assertEquals(
        0, subprocess.call([self.client, 'http://localhost:%d/' % _PORT]))


class EndToEndSpdy3Tests(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.server = _run_server(_PORT, '-3')
    _check_server_up(_PORT)

  @classmethod
  def tearDownClass(cls):
    _kill_server(cls.server)

  def setUp(self):
    build_dir = os.environ.get('top_builddir', '..')
    self.client = '%s/examples/spdycat' % build_dir

  def testSimpleRequest(self):
    self.assertEquals(
        0, subprocess.call([self.client, 'http://localhost:%d/' % _PORT]))


if __name__ == '__main__':
  unittest.main()
