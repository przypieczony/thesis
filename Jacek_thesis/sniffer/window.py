#! /usr/bin/python

import sys, os, time
from PyQt4 import QtGui, QtCore
from sniff import *
import thread

doSniff = 0

class MainWindow(QtGui.QMainWindow):

    def __init__(self):
        super(MainWindow, self).__init__()
        self.windowInitialize()

    def windowInitialize(self):
        newAction = QtGui.QAction(QtGui.QIcon('img/new.png'), 'New', self)
        newAction.setShortcut('Ctrl+N')
        newAction.setStatusTip('New file')
        newAction.triggered.connect(self.newFile)

        saveAction = QtGui.QAction(QtGui.QIcon('img/save.png'), 'Save', self)
        saveAction.setShortcut('Ctrl+S')
        saveAction.setStatusTip('Save to file')
        saveAction.triggered.connect(self.saveFile)

        openAction = QtGui.QAction(QtGui.QIcon('img/open.png'), 'Open', self)
        openAction.setShortcut('Ctrl+O')
        openAction.setStatusTip('Open a file')
        openAction.triggered.connect(self.openFile)

        closeAction = QtGui.QAction(QtGui.QIcon('img/exit.png'), 'Close', self)
        closeAction.setShortcut('Ctrl+Q')
        closeAction.setStatusTip('Close')
        closeAction.triggered.connect(self.close)
        
        startSniffAction = QtGui.QAction(QtGui.QIcon('img/start.png'), 'Start', self)
        startSniffAction.setStatusTip('Start')
        startSniffAction.triggered.connect(startLongSniff)
        
        stopSniffAction = QtGui.QAction(QtGui.QIcon('img/stop.png'), 'Stop', self)
        stopSniffAction.setStatusTip('Stop')
        stopSniffAction.triggered.connect(stopSniff)
        
        transportProtocols = QtGui.QComboBox(self)
        transportProtocols.addItem('UDP')
        transportProtocols.addItem('TCP')
        
        menubar = self.menuBar()
        fileMenu = menubar.addMenu('&File')
        fileMenu.addAction(newAction)
        fileMenu.addAction(saveAction)
        fileMenu.addAction(openAction)
        fileMenu.addAction(closeAction)

        toolbar = self.addToolBar('Toolbar')
        toolbar.addAction(newAction)
        toolbar.addAction(saveAction)
        toolbar.addAction(openAction)
        toolbar.addAction(closeAction)
        toolbar.insertSeparator(startSniffAction)
        toolbar.addAction(startSniffAction)
        toolbar.addAction(stopSniffAction)
        toolbar.addWidget(transportProtocols)
        
        fileMenu = menubar.addMenu('&Sniff')
        fileMenu.addAction(startSniffAction)
        fileMenu.addAction(stopSniffAction)

        self.main_widget = MainWidget(self)
        self.setCentralWidget(self.main_widget)
        self.setGeometry(300,300,800,800)
        self.setWindowTitle('VoIP analyser')
        self.show()

    def newFile(self):
        self.main_widget.textLeft.clear()
        self.main_widget.textRight.clear()

    def saveFile(self):
        filename = QtGui.QFileDialog.getSaveFileName(self, 'Save File', os.getenv('HOME'))
        f = open(filename, 'w')
        filedata = self.main_widget.textLeft.toPlainText()
        f.write(filedata)
        f.close()
        f = open(filename+'.schema', 'w')
        filedata = self.main_widget.textRight.toPlainText()
        f.write(filedata)
        f.close()
        
    def openFile(self):
        filename = QtGui.QFileDialog.getOpenFileName(self, 'Open File', os.getenv('HOME'))
        f = open(filename, 'r')
        filedata = f.read()
        self.main_widget.textLeft.setText(filedata)
        f.close()
        f = open(filename+'.schema', 'r')
        filedata = f.read()
        self.main_widget.textRight.setText(filedata)
        f.close()
        

class MainWidget(QtGui.QWidget):
    def __init__(self, parent):
        super(MainWidget, self).__init__(parent)
        self.layout = QtGui.QGridLayout(self)
        
        self.textLeft = QtGui.QTextEdit(self)
        self.textLeft.setCurrentFont(QtGui.QFont("Courier New"))
        
        self.textRight = QtGui.QTextEdit(self)
        self.textRight.setCurrentFont(QtGui.QFont("Courier New"))
        
        self.layout.addWidget(self.textLeft, 1, 0)
        self.layout.addWidget(self.textRight, 1, 1)

    def printText(self, textEdit, textToPrint):
        if textEdit == 'left':
            self.textLeft.append(textToPrint)
        elif textEdit == 'right':
            self.textRight.append(textToPrint)

def startLongSniff():
    infoStartStop('starting')
    thread.start_new_thread(startSniff,())

def startSniff():
    global doSniff
    doSniff = 1
    while doSniff:
        sniff_results=sniff('UDP')
        if sniff_results:
            window.main_widget.printText('left', sniff_results['message'])
            window.main_widget.printText('right', sniff_results['graph'])

def stopSniff():
    infoStartStop('stopping')
    global doSniff
    doSniff = 0
    
def infoStartStop(state):
    for side in ('left','right'):
        window.main_widget.printText(side,'...'+state+' at: '+time.strftime("%d.%m.%Y %H:%M:%S")+'...')

if __name__ == '__main__':
    app = QtGui.QApplication(sys.argv)
    window = MainWindow()
    sys.exit(app.exec_())
