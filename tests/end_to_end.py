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


def _run_server(port):
  srcdir = os.environ.get('srcdir', '.')
  testdata = '%s/testdata' % srcdir
  top_builddir = os.environ.get('top_builddir', '..')
  return subprocess.Popen([
      '%s/examples/spdyd' % top_builddir, str(port),
      '-d', testdata,
      '%s/privkey.pem' % testdata,
      '%s/cacert.pem' % testdata])

def _check_server_up(port):
  # Check this check for now.
  time.sleep(1)

def _kill_server(server):
  while server.returncode is None:
    server.terminate()
    time.sleep(1)
    server.poll()


class EndToEndSpdyTests(unittest.TestCase):
  def setUp(self):
    build_dir = os.environ.get('top_builddir', '..')
    self.client = '%s/examples/spdycat' % build_dir

  def testSimpleRequest(self):
    self.assertEquals(
        0, subprocess.call([self.client, 'http://localhost:%d/' % _PORT]))


class TestProgram(unittest.TestProgram):
  def runTests(self):
    self.testRunner = unittest.TextTestRunner()
    result = self.testRunner.run(self.test)
    self.successful = result.wasSuccessful()


def main():
  server = _run_server(_PORT)
  _check_server_up(_PORT)
  result = TestProgram()
  _kill_server(server)
  return not result.successful

if __name__ == '__main__':
  sys.exit(main())
