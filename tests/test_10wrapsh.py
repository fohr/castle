
from tests import Suite
import unittest
import os
import fnmatch

setup = False

class FsTests(unittest.TestCase):
    def setUp(self):
        global setup

        if setup == True:
            return
        setup = True

        self.target.run('/bin/mkdir -p /tmp/fstests')
        dir = os.path.join(os.path.split(self.dir)[0], 'user', 'utils', 'tests')
        for file in os.listdir(dir):
            if fnmatch.fnmatch(file, '*'):
                self.target.sftpPut(os.path.join(dir, file), 
                                    os.path.join('/tmp/fstests', file))
        self.target.run('/usr/bin/killall fsd')
        self.target.run('/bin/chmod 755 /tmp/fstests/single-castle-fs-test.sh')

    def runShellTest(self, testName):
        (rv, output) = self.target.output('/tmp/fstests/single-castle-fs-test.sh %s' % testName)
        self.assertTrue(rv == 0)

    def testHelloWorld(self):
        self.runShellTest('00-hello-world')

    def testTwoSnapshots(self):
        self.runShellTest('10-two-snapshots')

    def testRegions(self):
        self.runShellTest('20-regions')

    def testTransfers(self):
        self.runShellTest('30-transfers')

    def testLargeVolume(self):
        self.runShellTest('40-large-volume')

    def testNSnapshots(self):
        self.runShellTest('50-n-snapshots')

    def testExt3Init(self):
        self.runShellTest('60-ext3-init')

    def testExt3SingleFile(self):
        self.runShellTest('61-ext3-single-file')

    def testExt3RandomFile(self):
        self.runShellTest('62-ext3-random-file')

    def testExt3Snapshots(self):
        self.runShellTest('63-ext3-snapshots')

class MySuite(Suite):
    def __init__(self):
        testNames = """HelloWorld TwoSnapshots Regions Transfers
                       LargeVolume NSnapshots Ext3Init Ext3SingleFile
                       Ext3RandomFile Ext3Snapshots""".split()
        testNames = map(lambda i: "test" + i, testNames)
        super(MySuite, self).__init__(FsTests, testNames)

def run():
    print "done this"
