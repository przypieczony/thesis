#! /usr/bin/python

import sys
import pjsua as pj

def log_cb(level, str, len):
    print str,

class MyCallCallback(pj.CallCallback):
    def __init__(self, call=None):
        pj.CallCallback.__init__(self, call)

    def on_media_state(self):
        global library
        if self.call.info().media_state == pj.MediaState.ACTIVE:
            # Connect the call to sound device
            call_slot = self.call.info().conf_slot
            library.conf_connect(call_slot, 0)
            library.conf_connect(0, call_slot)
            print "Hello world, I can talk!"
def call(URI):
    try:
        library = pj.Lib()
        library.init(log_cfg = pj.LogConfig(level=3, callback=log_cb))
        transport = library.create_transport(pj.TransportType.UDP)
        library.start()
        acc = library.create_account_for_transport(transport)
        call = acc.make_call(URI[1], MyCallCallback())
        library.destroy()
        library = None
    except pj.Error, e:
        print "Exception: " + str(e)
        library.destroy()
        library = None
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "As an argument URI should be passed!"
        sys.exit(1)
    else:
        call(sys.argv)
