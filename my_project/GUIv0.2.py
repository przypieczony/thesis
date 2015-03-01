# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'GUI.ui'
#
# Created: Sat Feb 14 14:42:57 2015
#      by: PyQt4 UI code generator 4.10.3
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui
import socket

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName(_fromUtf8("MainWindow"))
        MainWindow.resize(699, 528)
        self.centralwidget = QtGui.QWidget(MainWindow)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))
        self.gridLayout = QtGui.QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.tabWidget = QtGui.QTabWidget(self.centralwidget)
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))
        self.Inputdata = QtGui.QWidget()
        self.Inputdata.setObjectName(_fromUtf8("Inputdata"))
        self.simulateRadioButton = QtGui.QRadioButton(self.Inputdata)
        self.simulateRadioButton.setEnabled(True)
        self.simulateRadioButton.setGeometry(QtCore.QRect(560, 10, 116, 22))
        self.simulateRadioButton.setCheckable(True)
        self.simulateRadioButton.setChecked(True)
        self.simulateRadioButton.setObjectName(_fromUtf8("simulateRadioButton"))
        self.layoutWidget = QtGui.QWidget(self.Inputdata)
        self.layoutWidget.setGeometry(QtCore.QRect(20, 40, 191, 220))
        self.layoutWidget.setObjectName(_fromUtf8("layoutWidget"))
        self.verticalLayout = QtGui.QVBoxLayout(self.layoutWidget)
        self.verticalLayout.setMargin(0)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.label = QtGui.QLabel(self.layoutWidget)
        self.label.setObjectName(_fromUtf8("label"))
        self.verticalLayout.addWidget(self.label)
        self.sourceAddressField = QtGui.QLineEdit(self.layoutWidget)
        self.sourceAddressField.setStatusTip(_fromUtf8(""))
        self.sourceAddressField.setInputMethodHints(QtCore.Qt.ImhPreferNumbers)
        self.sourceAddressField.setInputMask(_fromUtf8(""))
        self.sourceAddressField.setText(_fromUtf8(""))
        self.sourceAddressField.setObjectName(_fromUtf8("sourceAddressField"))
        self.verticalLayout.addWidget(self.sourceAddressField)
        self.label_2 = QtGui.QLabel(self.layoutWidget)
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.verticalLayout.addWidget(self.label_2)
        self.sourcePortField = QtGui.QLineEdit(self.layoutWidget)
        self.sourcePortField.setStatusTip(_fromUtf8(""))
        self.sourcePortField.setInputMethodHints(QtCore.Qt.ImhPreferNumbers)
        self.sourcePortField.setInputMask(_fromUtf8(""))
        self.sourcePortField.setText(_fromUtf8(""))
        self.sourcePortField.setObjectName(_fromUtf8("sourcePortField"))
        self.verticalLayout.addWidget(self.sourcePortField)
        self.label_3 = QtGui.QLabel(self.layoutWidget)
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.verticalLayout.addWidget(self.label_3)
        self.destAddresField = QtGui.QLineEdit(self.layoutWidget)
        self.destAddresField.setStatusTip(_fromUtf8(""))
        self.destAddresField.setInputMethodHints(QtCore.Qt.ImhPreferNumbers)
        self.destAddresField.setInputMask(_fromUtf8(""))
        self.destAddresField.setText(_fromUtf8(""))
        self.destAddresField.setObjectName(_fromUtf8("destAddresField"))
        self.verticalLayout.addWidget(self.destAddresField)
        self.label_4 = QtGui.QLabel(self.layoutWidget)
        self.label_4.setObjectName(_fromUtf8("label_4"))
        self.verticalLayout.addWidget(self.label_4)
        self.destPortField = QtGui.QLineEdit(self.layoutWidget)
        self.destPortField.setStatusTip(_fromUtf8(""))
        self.destPortField.setInputMethodHints(QtCore.Qt.ImhPreferNumbers)
        self.destPortField.setInputMask(_fromUtf8(""))
        self.destPortField.setText(_fromUtf8(""))
        self.destPortField.setObjectName(_fromUtf8("destPortField"))
        self.verticalLayout.addWidget(self.destPortField)
        self.layoutWidget1 = QtGui.QWidget(self.Inputdata)
        self.layoutWidget1.setGeometry(QtCore.QRect(460, 390, 211, 29))
        self.layoutWidget1.setObjectName(_fromUtf8("layoutWidget1"))
        self.horizontalLayout = QtGui.QHBoxLayout(self.layoutWidget1)
        self.horizontalLayout.setMargin(0)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.clearButton = QtGui.QPushButton(self.layoutWidget1)
        self.clearButton.setObjectName(_fromUtf8("clearButton"))
        self.horizontalLayout.addWidget(self.clearButton)
        self.acceptButton = QtGui.QPushButton(self.layoutWidget1)
        self.acceptButton.setObjectName(_fromUtf8("acceptButton"))
        self.horizontalLayout.addWidget(self.acceptButton)
        self.sipTemplate = QtGui.QTextBrowser(self.Inputdata)
        self.sipTemplate.setGeometry(QtCore.QRect(280, 70, 351, 291))
        self.sipTemplate.setObjectName(_fromUtf8("sipTemplate"))
        self.tabWidget.addTab(self.Inputdata, _fromUtf8(""))
        self.Register = QtGui.QWidget()
        self.Register.setObjectName(_fromUtf8("Register"))
        self.tabWidget.addTab(self.Register, _fromUtf8(""))
        self.gridLayout.addWidget(self.tabWidget, 0, 1, 1, 1)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtGui.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 699, 25))
        self.menubar.setObjectName(_fromUtf8("menubar"))
        self.menuFile = QtGui.QMenu(self.menubar)
        self.menuFile.setObjectName(_fromUtf8("menuFile"))
        self.menuEdit = QtGui.QMenu(self.menubar)
        self.menuEdit.setObjectName(_fromUtf8("menuEdit"))
        self.menuExit = QtGui.QMenu(self.menubar)
        self.menuExit.setObjectName(_fromUtf8("menuExit"))
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtGui.QStatusBar(MainWindow)
        self.statusbar.setObjectName(_fromUtf8("statusbar"))
        MainWindow.setStatusBar(self.statusbar)
        self.actionAdd_template = QtGui.QAction(MainWindow)
        self.actionAdd_template.setObjectName(_fromUtf8("actionAdd_template"))
        self.menuFile.addAction(self.actionAdd_template)
        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuEdit.menuAction())
        self.menubar.addAction(self.menuExit.menuAction())

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QObject.connect(self.clearButton, QtCore.SIGNAL(_fromUtf8("clicked()")), self.sourceAddressField.clear)
        QtCore.QObject.connect(self.clearButton, QtCore.SIGNAL(_fromUtf8("clicked()")), self.sourcePortField.clear)
        QtCore.QObject.connect(self.clearButton, QtCore.SIGNAL(_fromUtf8("clicked()")), self.destAddresField.clear)
        QtCore.QObject.connect(self.clearButton, QtCore.SIGNAL(_fromUtf8("clicked()")), self.destPortField.clear)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow", None))
        MainWindow.setStatusTip(_translate("MainWindow", "Ready", None))
        self.simulateRadioButton.setText(_translate("MainWindow", "Simulation", None))
        self.label.setText(_translate("MainWindow", "Enter source address:", None))
        self.sourceAddressField.setPlaceholderText(_translate("MainWindow", "e. g.192.168.100.1", None))
        self.label_2.setText(_translate("MainWindow", "Enter source port:", None))
        self.sourcePortField.setPlaceholderText(_translate("MainWindow", "e.g. 5060", None))
        self.label_3.setText(_translate("MainWindow", "Enter destiantion address:", None))
        self.destAddresField.setPlaceholderText(_translate("MainWindow", "e. g.192.168.100.2", None))
        self.label_4.setText(_translate("MainWindow", "Enter destination port:", None))
        self.destPortField.setPlaceholderText(_translate("MainWindow", "e.g. 5060", None))
        self.clearButton.setText(_translate("MainWindow", "Clear", None))
        self.acceptButton.setText(_translate("MainWindow", "Accept", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.Inputdata), _translate("MainWindow", "Input data", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.Register), _translate("MainWindow", "Register", None))
        self.menuFile.setTitle(_translate("MainWindow", "File", None))
        self.menuEdit.setTitle(_translate("MainWindow", "Edit", None))
        self.menuExit.setTitle(_translate("MainWindow", "Exit", None))
        self.actionAdd_template.setText(_translate("MainWindow", "Add template", None))
        self.acceptButton.clicked.connect(self.getParameters)


    def getParameters(self):
        """This function captures input parameters"""

        self.sipTemplate.showMessage('rable')

        self.sourceAddress = str(self.sourceAddressField.text())
        self.destAddress = str(self.destAddresField.text())
        if self.sourceAddress != self.destAddress:
            try:
                socket.inet_aton(self.sourceAddress)
                socket.inet_aton(self.destAddress)
            except socket.error:
                self.statusbar.showMessage('Error! Wrong ip address')
        else:
            self.statusbar.showMessage('Error! ip address are the same')
        try:
            self.sourcePort = int(self.sourcePortField.text())
            self.destPort = int(self.destPortField.text())
        except ValueError:
            self.statusbar.showMessage('Error! Empty port number, choose between 1024-65535')
        if (self.sourcePort < 1024 or self.sourcePort > 65535) or \
            (self.destPort < 1024 or self.destPort > 65535):
            self.statusbar.showMessage('Error! Wrong port number, choose between 1024-65535')

        if self.simulateRadioButton.isChecked():
            random_loopback = "127.{}.{}.{}".format(random.randint(1,255), \
                random.randint(1,255), random.randint(1,255))
            sourceAddress = random_loopback
            destAddress = "127.0.0.1"
            

    def main():
        # usage = """%prog [OPTIONS]"""
        # opt = optparse.OptionParser(usage=usage)

        # opt.add_option('-c', dest='count', type='int', default=sys.maxint,
        #                        help='Total number of queries to send')

        # opt.add_option('-i', dest='wait', type='float', default=1,
        #                        help='Specify packet send interval time in seconds')
        
        # opt.add_option('-T', dest='timeout', type='float', default=1,
        #                        help='Specify receiving timeout in seconds')

        # opt.add_option('-v', dest='var', type='string', default=[""], action='append',
        #                        help='add a template variable in format varname:value')

        # opt.add_option('-V', dest='verbose', default=False, action='store_true',
        #                        help='be verbose dumping full requests / responses')

        # opt.add_option('-q', dest='quiet', default=False, action='store_true',
        #                        help='be quiet and never print any report')

        # opt.add_option('-a', dest='aggressive', default=False, action='store_true',
        #                        help='aggressive mode: ignore any response')

        # opt.add_option('-S', dest='sourceAddress', type='string', default="0.0.0.0",
        #                        help='Specify ip address to bind for sending and receiving UDP datagrams')

        # opt.add_option('-P', dest='source_port', type='int', default=5060,
        #                        help='Specify the port number to use as a source port in UDP datagrams')

        # opt.add_option('-d', dest='dest_ip', type='string', default=None,
        #                        help='*mandatory* Specify the destination ip address')

        # opt.add_option('-p', dest='dest_port', type='int', default=5060,
        #                        help='*mandatory* Specify the destination port number')

        # opt.add_option('-r', dest='request_template', type='string', default=None,
        #                        help='Specify the request template file')

        # opt.add_option('-t', dest='print_template', action="store_true", default=False, 
        #                         help='print the default request template')
        
        # opt.add_option('-m', dest='modules', type='string', default=[], action='append',
        #                        help='load additionals Python modules used in Python interpreted template variables')
        
        # opt.add_option('-O', dest='out_regex', type='string', default="",
        #                        help='regex to apply to response received, (default \'(.*\n)*\')')

        # opt.add_option('-R', dest='out_replace', type='string', default="",
        #         help='print this replace string applied to the response')

        # opt.add_option('-x', dest='simulate', action="store_true", default=False,
        #                        help='simulates ip addresses')

        # options, args = opt.parse_args(sys.argv[1:])
        
        # if options.print_template:
        #     sys.stderr.write("%s\n" % def_request)
        #     sys.exit()
        
        # for m in options.modules:
        #     globals()[m] = __import__(m)
        
        template_vars = {
            "source_ip": sourceAddress,
            "source_port": sourcePort,
            "dest_ip": destAddress,
            "dest_port": destPort
        }

        # first var is empty by default. It has to be analyzed deeper
        # for v in options.var[1:]:
        #     try:
        #         key = v.split(":")[0]
        #         val = ":".join(v.split(":")[1:])
        #         template_vars.update({key: val})
        #     except IndexError:
        #         sys.stderr.write("ERROR: variables must be in format name:value. %s\n" % v)
        #         opt.print_help()
        #         sys.exit() 
            
        if options.verbose:
            sys.stderr.write("=======================================\n")
            sys.stderr.write("I'm using these variables in templates: \n")
            sys.stderr.write("=======================================\n")
            for k in template_vars:
                sys.stderr.write("%s: %s\n" % (k, template_vars[k]))
            sys.stderr.write("=======================================\n\n")

        count = options.count
        try:
            sending_sock = open_sock(options, options.source_ip, options.source_port)
            receiving_sock = open_sock(options, options.dest_ip, options.dest_port)
        except Exception, e:
            sys.stderr.write("ERROR: cannot open socket. %s with address %s\n" % (e, options.source_ip))
            sys.exit(-1)

        sent = rcvd = ok_recvd = notify_recvd = 0 
        
        try:
            for req in gen_request(template_vars, options):
                try:
                    sip_req = Request(req)
                    #Add Content-Lenght if missing
                    if "content-length" not in sip_req.headers:
                        sip_req.headers["content-length"] = len(sip_req.body)
                    
                    try:    
                        sending_sock.sendto(str(sip_req),(options.dest_ip, options.dest_port))
                    except Exception, e:
                        sys.stderr.write("ERROR: cannot send packet to %s:%d. %s\n" % (options.dest_ip, options.dest_port, e))
                    if not options.quiet:
                        sys.stderr.write("sent Request %s to %s:%d cseq=%s len=%d\n" % (sip_req.method, template_vars['dest_ip'], options.dest_port, sip_req.headers['cseq'].split()[0], len(str(sip_req))))
                        if options.verbose:
                            sys.stderr.write("\n=== Full Request sent ===\n\n")
                            sys.stderr.write("%s\n" % sip_req)
                    sent += 1
                    

                    if not options.aggressive:
                        #import pdb; pdb.set_trace()
                        read = [receiving_sock]
                        inputready,outputready,exceptready = select.select(read,[],[],options.timeout)
                    
                        for s in inputready:
                            if s == receiving_sock:
                                buf = None
                                buf = receiving_sock.recvfrom(0xffff)
                                print_reply(buf, template_vars, options.out_regex, options.out_replace, verbose=options.verbose, quiet=options.quiet)
                                rcvd += 1
        
                except socket.timeout:
                    pass
                time.sleep(options.wait)
        except KeyboardInterrupt:
            pass

        if not options.quiet:
            sys.stderr.write('\n--- statistics ---\n')
            sys.stderr.write('%d packets transmitted, %d packets received, %.1f%% packet loss\n' % (sent, rcvd, (float(sent - rcvd) / sent) * 100))




if __name__ == "__main__":
    import sys
    app = QtGui.QApplication(sys.argv)
    MainWindow = QtGui.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())

