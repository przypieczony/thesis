import re, socket, struct
from kutil import getlocaladdr
# def getlocaladdr(sock=None):
#     '''Get the local ('addr', port) for the given socket. It uses the
#     getsockname() to get the local IP and port. If the local IP is '0.0.0.0'
#     then it uses gethostbyname(gethostname()) to get the local IP. The
#     returned object's repr gives 'ip:port' string. If the sock is absent, then
#     just gets the local IP and sets the port part as 0. This functions is used
#     by class TransportInfo
#     '''
#     global _local_ip
#     # TODO: use a better mechanism to get the address such as getifaddr
#     addr = sock and sock.getsockname() or ('0.0.0.0', 0)
#     if addr and addr[0] == '0.0.0.0': 
#         addr = (_local_ip if _local_ip else socket.gethostbyname(socket.gethostname()), addr[1])
#     return addr

def isIPv4(data):
    try:
        m = socket.inet_aton(data) # alternatively: len(filter(lambda y: int(y) >= 0 and int(y) < 256, data.split('.', 3))) == 4
        return True
    except:
        return False

def isMulticast(data):
    try:
        m, = struct.unpack('>I', socket.inet_aton(data))
        return ((m & 0xF0000000) == 0xE0000000) # class D: 224.0.0.0/4 or first four bits as 0111
    except:
        return False

#Some methods to format strings in message:
_address = ['contact', 'from', 'record-route', 'refer-to', 'referred-by', 'route', 'to']
_comma = ['authorization', 'proxy-authenticate', 'proxy-authorization', 'www-authenticate']
_unstructured = ['call-id', 'cseq', 'date', 'expires', 'max-forwards', 'organization', 'server', 'subject', 'timestamp', 'user-agent']
_short = ['allow-events', 'u', 'call-id', 'i', 'contact', 'm', 'content-encoding', 'e', 'content-length', 'l', 'content-type', 'c', 'event', 
'o', 'from', 'f', 'subject', 's', 'supported', 'k', 'to', 't', 'via', 'v']

_exception = {'call-id':'Call-ID','cseq':'CSeq','www-authenticate':'WWW-Authenticate'}

def _canon(s):
    s = s.lower()
    return ((len(s)==1) and s in _short and _canon(_short[_short.index(s)-1])) \
    or (s in _exception and _exception[s]) or'-'.join([x.capitalize() for x in s.split('-')])

_quote = lambda s: '"' + s + '"' if s[0] != '"' != s[-1] else s
_unquote = lambda s: s[1:-1] if s[0] == '"' == s[-1] else s
#Here are these methods ends

class Header(object):

    def __init__(self, value=None, name=None):
        self.name = name and _canon(name.strip()) or None
        self.value = self._parse(value.strip(), self.name and self.name.lower() or None)

    def __str__(self):
        name = self.name.lower()
        rest = '' if ((name in _comma) or (name in _unstructured)) \
          else (';'.join(map(lambda x: self.__dict__[x] and '%s=%s'%(x.lower(),self.__dict__[x]) or x, filter(lambda x: 
            x.lower() not in ['name','value', '_viauri'], self.__dict__))))
        return str(self.value) + (rest and (';'+rest) or'');

    def __repr__(self):
        return self.name + ": " + str(self)

    def __getitem__(self, name): returnself.__dict__.get(name.lower(), None)
    def __setitem__(self, name, value): self.__dict__[name.lower()] = value
    def __contains__(self, name): return name.lower() in self.__dict__

    def dup(self):
        return Header(self.__str__(), self.name)

    def _parse(self, value, name):
        if name in _address: # parse as address-based header
            addr = Address(); addr.mustQuote = True
            count = addr.parse(value)
            value, rest = addr, value[count:]
            if rest:
                for n,sep,v in map(lambda x: x.partition('='), rest.split(';') if rest else []):
                    if n.strip():
                        self.__dict__[n.lower().strip()] = v.strip()
        elif name not in _comma and name not in _unstructured: # parse as standard header
            value, sep, rest = value.partition(';')
            for n,sep,v in map(lambda x: x.partition('='), rest.split(';')if rest else []):
                self.__dict__[n.lower().strip()] = v.strip()
        if name in _comma: # parse as comma-included header
            self.authMethod, sep, rest = value.strip().partition(' ')
            for n,v in map(lambda x: x.strip().split('='), rest.split(',') if rest else []):
                self.__dict__[n.lower().strip()] = _unquote(v.strip())
        elif name == 'cseq':
            n, sep, self.method = map(lambda x: x.strip(), value.partition(' '))
            self.number = int(n); value = n + ' ' + self.method
        return value

    @property
    def viaUri(self):
        if not hasattr(self, '_viaUri'):
            if self.name != 'Via': raise ValueError, 'viaUri available only on Via header'
            proto, addr = self.value.split(' ')
            type = proto.split('/')[2].lower()  # udp, tcp, tls
            self._viaUri = URI('sip:' + addr + ';transport=' + type)
            if self._viaUri.port == None: self._viaUri.port = 5060
            if 'rport' in self:
                try: self._viaUri.port = int(self.rport)
                except: pass # probably not an int
            if type not in ['tcp','sctp','tls']:
                if 'maddr' in self: self._viaUri.host = self.maddr
                elif 'received' in self: self._viaUri.host = self.received
        return self._viaUri

    @staticmethod
    def createHeaders(value):
        '''Parse a header line and return (name, [Header, Header, Header]) where name
        represents the header name, and the list has list of Header objects, typically
        one but for comma separated header line there can be multiple.
        '''
        name, value = map(str.strip, value.split(':', 1))
        return (_canon(name), map(lambda x: Header(x, name), value.split(',') if name.lower() not in _comma else [value]))




class URI(object):
    '''A URI object with dynamic properties.
    Attributes and items such as scheme, user, password, host, port, 
    param[name], header[index], give various parts of the URI.'''

    
    # regular expression for URI syntax.
    # TODO: need to extend for host portion.
    _syntax = re.compile('^(?P<scheme>[a-zA-Z][a-zA-Z0-9\+\-\.]*):'  # scheme
            + '(?:(?:(?P<user>[a-zA-Z0-9\-\_\.\!\~\*\'\(\)&=\+\$,;\?\/\%]+)' # user
            + '(?::(?P<password>[^:@;\?]+))?)@)?' # password
            + '(?:(?:(?P<host>[^;\?:]*)(?::(?P<port>[\d]+))?))'  # host, port
            + '(?:;(?P<params>[^\?]*))?' # parameters
            + '(?:\?(?P<headers>.*))?$') # headers
    
    def __init__(self, value=''):
        if value:
            m = URI._syntax.match(value)
            if not m: raise ValueError, 'Invalid URI: (' + value + ')'
            self.scheme, self.user, self.password, self.host, self.port, params, headers = m.groups()
            if self.scheme == 'tel' and self.user is None:
                self.user, self.host = self.host, None
            self.port = self.port and int(self.port) or None
            self.header = [nv for nv in headers.split('&')] if headers else []

            splits = map(lambda n: n.partition('='), params.split(';')) if params else []
            self.param = dict(map(lambda k: (k[0], k[2] if k[2] else None), splits)) if splits else {}
        else:
            self.scheme = self.user = self.password = self.host = self.port = None
            self.param = {}; self.header = []

    def __repr__(self):
        user, host = (self.user, self.host) if self.scheme != 'tel' else (None, self.user)
        return (self.scheme + ':' + ((user + \
          ((':'+self.password) if self.password else '') + '@') if user else '') + \
          (((host if host else '') + ((':'+str(self.port)) if self.port else '')) if host else '') + \
          ((';'+';'.join([(n+'='+v if v is not None else n) for n,v in self.param.items()])) if len(self.param)>0 else '') + \
          (('?'+'&'.join(self.header)) if len(self.header)>0 else '')) if self.scheme and host else '';

    def dup(self):
        return URI(self.__repr__())

    def __hash__(self):
        return hash(str(self).lower())

    def __cmp__(self, other):
        return cmp(str(self).lower(), str(other).lower())

    @property
    def hostPort(self):
        return (self.host, self.port)

    def _ssecure(self, value):
        if value and self.scheme in ['sip', 'http']: self.scheme += 's'
    def _gsecure(self):
        return True if self.scheme in ['sips', 'https'] else False
    secure = property(fget=_gsecure, fset=_ssecure)



class Address(object):
    _syntax = [re.compile('^(?P<name>[a-zA-Z0-9\-\.\_\+\~\ \t]*)<(?P<uri>[^>]+)>'),
      re.compile('^(?:"(?P<name>[a-zA-Z0-9\-\.\_\+\~\ \t]+)")[\ \t]*<(?P<uri>[^>]+)>'),
      re.compile('^[\ \t]*(?P<name>)(?P<uri>[^;]+)')]

    def __init__(self, value=None):
        self.displayName = self.uri = None
        self.wildcard = self.mustQuote = False
        if value: self.parse(value)
    
    def parse(self, value):
        if str(value).startswith('*'):
            self.wildcard = True
            return 1
        else:
            for regexp in Address._syntax:
                m = regexp.match(value)
                if m:
                    self.displayName = m.groups()[0].strip()
                    self.uri = URI(m.groups()[1].strip())
                    return m.end()

    def __repr__(self):
        return (('"' + self.displayName + '"' + (' ' if self.uri else '')) if self.displayName else '') \
          + ((('<' if self.mustQuote or self.displayName else '') \
          + repr(self.uri) \
          + ('>' if self.mustQuote or self.displayName else '')) if self.uri else '')

    def dup(self):
        return Address(self.__repr__())

    @property
    def displayable(self):
        name = self.displayName or self.uri and self.uri.user or self.uri and self.uri.host or ''
        return name if len(name)<25 else (name[0:22] + '...')

class Message(object):
    '''A SIP message object with dynamic properties.
    The header names can be accessed as attributes or items and
    are case-insensitive. Attributes such as method, uri (URI),
    response (int), responsetext, protocol, and body are available.
    Accessing an unavailable header gives None instead of exception.

    >>> m = Message()
    >>> m.method = 'INVITE'
    '''

    def __init__(self, value=None):
        self.method = self.uri = self.response = self.responsetext = self.protocol = self._body = None
        if value: self._parse(value)

    # non-header attributes or items
    _keywords = ['method','uri','response','responsetext','protocol','_body','body']
    # headers that can appear only atmost once. subsequent occurance ignored.
    _single = ['call-id', 'content-disposition', 'content-length', 'content-type', 'cseq', 'date', 'expires', 'event', 'max-forwards', 
    'organization', 'refer-to', 'referred-by', 'server', 'session-expires', 'subject', 'timestamp', 'to', 'user-agent']

    def __getattr__(self, name): returnself.__getitem__(name)
    def __getattribute__(self, name): return object.__getattribute__(self, name.lower())
    def __setattr__(self, name, value): object.__setattr__(self, name.lower(), value)
    def __delattr__(self, name): object.__delattr__(self, name.lower())
    def __hasattr__(self, name): object.__hasattr__(self, name.lower())
    def __getitem__(self, name): returnself.__dict__.get(name.lower(), None)
    def __setitem__(self, name, value): self.__dict__[name.lower()] = value
    def __contains__(self, name): return name.lower() in self.__dict__

    def _parse(self, value):
        firstheaders, body = value.split('\r\n\r\n', 1)
        firstline, headers = firstheaders.split('\r\n', 1)

        a, b, c = firstline.split(' ', 2)
        try: # try as response
            self.response, self.responsetext, self.protocol = int(b), c, a # throws error if b is not int.
        except: # probably a request
            self.method, self.uri, self.protocol = a, URI(b), c

        for h in headers.split('\r\n'):
            if h.startswith(r'[ \t]'):
                pass
            try:
                name, values = Header.createHeaders(h)
                if name not in self: # doesn't already exist
                    self[name] = values if len(values) > 1 else values[0]
                elif name not in Message._single: # valid multiple-instance header
                    if not isinstance(self[name],list): self[name] = [self[name]]
                    self[name] += values
            except:
                continue

        bodyLen = int(self['Content-Length'].value) if 'Content-Length' in self else 0
        if body: self.body = body
        if self.body != None and bodyLen != len(body):
            raise ValueError, 'Invalid content-length %d!=%d'%(bodyLen, len(body))
        for h in ['To','From','CSeq','Call-ID']: 
            if h not in self: raise ValueError, 'Mandatory header %s missing'%(h)

    def __repr__(self):
        '''Return the formatted message string.'''
        if self.method != None: m = self.method + ' ' + str(self.uri) + ' ' + self.protocol + '\r\n'
        elif self.response != None: m = self.protocol + ' ' + str(self.response) + ' ' + self.responsetext + '\r\n'
        else: returnNone # invalid message
        for h in self: 
            m += repr(h) + '\r\n'
        m+= '\r\n'
        if self.body != None: m += self.body
        return m

    def dup(self):
        return Message(self.__repr__())

    def __iter__(self):
        '''Return iterator to iterate over all Header objects.'''
        h = list()
        for n in filter(lambda x: not x.startswith('_') and x not in Message._keywords, self.__dict__):
            h += filter(lambda x: isinstance(x, Header), self[n] if isinstance(self[n],list) else [self[n]])
        return iter(h)

    def first(self, name):
        '''Return the first Header object for this name, or None.'''
        result = self[name]
        return isinstance(result,list) and result[0] or result

    def all(self, *args):
        '''Return list of the Header object (or empty list) for all the header names in args.'''
        args = map(lambda x: x.lower(), args)
        h = list()
        for n in filter(lambda x: x in args and not x.startswith('_') and x not in Message._keywords, self.__dict__):
            h += filter(lambda x: isinstance(x, Header), self[n] if isinstance(self[n],list) else [self[n]])
        return h

    def insert(self, header, append=False):
        if header and header.name:
            if header.name not in self:
                self[header.name] = header
            elif isinstance(self[header.name], Header):
                self[header.name] = (append and [self[header.name], header] or [header, self[header.name]])
            else:
                if append: self[header.name].append(header)
                else: self[header.name].insert(0, header)

    def body():
        '''The body property, when set also sets the Content-Length header field.'''
        def fset(self, value):
            self._body = value
            self['Content-Length'] = Header('%d'%(value and len(value) or 0), 'Content-Length')
        def fget(self):
            return self._body
        return locals()
    body = property(**body())


    @staticmethod
    def _populateMessage(m, headers=None, content=None):
        '''Modify m to add headers (list of Header objects) and content (str body)'''
        if headers: 
            for h in headers: m.insert(h, True) # append the header instead of overriding
        if content: m.body = content
        else: m['Content-Length'] = Header('0', 'Content-Length')

    @staticmethod
    def createRequest(method, uri, headers=None, content=None):
        '''Create a new request Message with given attributes.'''
        m = Message()
        m.method, m.uri, m.protocol = method, URI(uri), 'SIP/2.0'
        Message._populateMessage(m, headers, content)
        if m.CSeq != None and m.CSeq.method != method: m.CSeq = Header(str(m.CSeq.number) + ' ' + method, 'CSeq')
        return m

    @staticmethod
    def createResponse(response, responsetext, headers=None, content=None, r=None):
        '''Create a new response Message with given attributes.
        The original request may be specified as the r parameter.'''
        m = Message()
        m.response, m.responsetext, m.protocol = response, responsetext, 'SIP/2.0'
        if r: 
            m.To, m.From, m.CSeq, m['Call-ID'], m.Via = r.To, r.From, r.CSeq, r['Call-ID'], r.Via
            if response == 100: m.Timestamp = r.Timestamp
            Message._populateMessage(m, headers, content)
        return m


    for x in range(1,7):
        exec 'def is%dxx(self): return self.response and (self.response / 100 == %d)'%(x,x)
        exec 'is%dxx = property(is%dxx)'%(x,x)
    @property
    def isfinal(self): returnself.response and (self.response >= 200)

class TransportInfo:
    '''Transport information needed by Stack constructor'''
    def __init__(self, sock, secure=False):
        addr = getlocaladdr(sock)
        self.host, self.port = addr[0], addr[1]
        print "host: "+ self.host + " port: " + self.port
        self.type = (sock.type == socket.SOCK_DGRAM and 'udp' or 'tcp')
        self.secure = secure
        self.reliable = self.congestionControlled = (sock.type==socket.SOCK_STREAM)

class App():
        def send(self, data, dest): pass
            #'to send data (str) to dest ('192.1.2.3', 5060).'
        def sending(self, data, dest): pass
            #'to indicate that a given data (Message) will be sent to the dest (host, port).'
        def createServer(self, request, uri): return UserAgent(stack, request)
            #'to ask the application to create a UAS for this request (Message) from source uri (Uri).'
        def receivedRequest(self, ua, request): pass
            #'to inform that the UAS or Dialog has recived a new request (Message).'
        def receivedResponse(self, ua, request): pass
            #'to inform that the UAC or Dialog has recived a new response (Message).'
        def cancelled(self, ua, request): pass
            #'to inform that the UAS or Dialog has received a cancel for original request (Message).'
        def dialogCreated(self, dialog, ua): pass
            #'to inform that the a new Dialog is created from the old UserAgent.'
        def authenticate(self, ua, header): header.password='mypass'; return True
            #'to ask the application for credentials for this challenge header (Header).'
        def createTimer(self, cbObj): return timerObject
            #'the returned timer object must have start() and stop() methods, a delay (int)'

class Stack(object):
    '''The SIP stack is associated with transport layer and controls message
    flow among different layers.

    The application must provide an app instance with following signature:
    class App():
        def send(self, data, dest): pass
            'to send data (str) to dest ('192.1.2.3', 5060).'
        def sending(self, data, dest): pass
            'to indicate that a given data (Message) will be sent to the dest (host, port).'
        def createServer(self, request, uri): return UserAgent(stack, request)
            'to ask the application to create a UAS for this request (Message) from source uri (Uri).'
        def receivedRequest(self, ua, request): pass
            'to inform that the UAS or Dialog has recived a new request (Message).'
        def receivedResponse(self, ua, request): pass
            'to inform that the UAC or Dialog has recived a new response (Message).'
        def cancelled(self, ua, request): pass
            'to inform that the UAS or Dialog has received a cancel for original request (Message).'
        def dialogCreated(self, dialog, ua): pass
            'to inform that the a new Dialog is created from the old UserAgent.'
        def authenticate(self, ua, header): header.password='mypass'; return True
            'to ask the application for credentials for this challenge header (Header).'
        def createTimer(self, cbObj): return timerObject
            'the returned timer object must have start() and stop() methods, a delay (int)
            attribute, and should invoke cbObj.timedout(timer) when the timer expires.'
    Only the authenticate and sending methods are optional. All others are mandatory.

    The application must invoke the following callback on the stack:
    stack.received(data, src)
        'when incoming data (str) received on underlying transport from
        src ('192.2.2.2', 5060).'

    The application must provide a Transport object which is an object with
    these attributes: host, port, type, secure, reliable, congestionControlled, where
        host: a string representing listening IP address, e.g., '192.1.2.3'
        port: a int representing listening port number, e.g., 5060.
        type: a string of the form 'udp', 'tcp', 'tls', or 'sctp' indicating the transport type.
        secure: a boolean indicating whether this is secure or not?
        reliable: a boolean indicating whether the transport is reliable or not?
        congestionControlled: a boolean indicating whether the transport is congestion controlled?
    '''

    def __init__(self, app, transport):
        '''Construct a stack using the specified application (higher) layer and
        transport (lower) data.'''
        self.tag = str(random.randint(0,2**31))
        self.app, self.transport = app, transport
        self.closing = False
        self.dialogs, self.transactions = dict(), dict()
        self.serverMethods = ['INVITE','BYE','MESSAGE','SUBSCRIBE','NOTIFY']

    def __del__(self):
        self.closing = True
        for d in self.dialogs: del self.dialogs[d]
        for t in self.transactions: del self.transactions[t]
        del self.dialogs; del self.transactions

    @property
    def uri(self): 
        transport = self.transport
        return URI(((transport.type == 'tls') and 'sips' or'sip') + ':' + transport.host + ':' + str(transport.port))

    @property
    def newCallId(self): 
        return str(random.randint(0,2**31)) + '@' + (self.transport.host or'localhost')

    def createVia(self, secure=False):
        if not self.transport: raise ValueError, 'No transport in stack'
        if secure and not self.transport.secure: raise ValueError, 'Cannot find a secure transport'
        return Header('SIP/2.0/' +self.transport.type.upper()+' '+self.transport.host + ':' + str(self.transport.port) + ';rport', 'Via')

    def send(self, data, addr, stack):
        '''Send a data (Message) to given dest (URI or hostPort), or using the Via header of
        response message if dest is missing.'''
        if dest and isinstance(dest, URI):
            if not uri.host: raise ValueError, 'No host in destination uri'
            dest = (dest.host, dest.port or self.transport.type == 'tls' and self.transport.secure and 5061 or 5060)
        if isinstance(data, Message):
            if data.method: # request
                if dest and isMulticast(dest[0]):
                    data.first('Via')['maddr'], data.first('Via')['ttl'] = dest[0], 1
            elif data.response: # response
                if not dest: 
                    dest = data.first('Via').viaUri.hostPort
        self.app.send(str(data), dest, stack=self)

    def received(self, data, src):
        try:
            m = Message(data)
            uri = URI((self.transport.secure and 'sips' or'sip') + ':' + str(src[0]) + ':' + str(src[1]))
            if m.method: 
                if m.Via == None: raise ValueError, 'No Via header in request'
                via = m.first('Via')
                if via.viaUri.host != src[0] or via.viaUri.port != src[1]: 
                    via['received'], via.viaUri.host = src[0], src[0]
                if 'rport' in via: via['rport'] = src[1]
                via.viaUri.port = src[1]
                self._receivedRequest(m, uri)
            elif m.response: 
                self._receivedResponse(m, uri)
            else: raise ValueError, 'Received invalid message'
        except ValueError, E: 
            if _debug: print 'Error in received message:', E

    def _receivedRequest(self, r, uri):
        branch = r.first('Via').branch
        if r.method == 'ACK' and branch == '0': 
            t = None
        else:
            t = self.findTransaction(Transaction.createId(branch, r.method))
        if not t:
            app = None # object through which new transaction is created
            if r.method != 'CANCEL' and 'tag' in r.To:
                d = self.findDialog(r)
                if not d: # no dialog found
                    if r.method != 'ACK':
                        self.send(Message.createResponse(481, 'Dialog does not exist', None, None, r))
                    else: # ACK
                        if not t and branch != '0': t = self.findTransaction(Transaction.createId(branch, 'INVITE'))
                        if t: t.receivedRequest(r)
                        else: print 'No existing transaction for ACK'
                        return
                else: # dialog found
                    app = d
            elif r.method != 'CANCEL': 
                u = self.createServer(r, uri)
                if u: 
                    app = u
                elif r.method == 'OPTIONS':
                    m = Message.createResponse(200, 'OK', None, None, r)
                    m.Allow = Header('INVITE, ACK, CANCEL, BYE, OPTIONS', 'Allow')
                    self.send(m)
                    return
                elif r.method != 'ACK': 
                    self.send(Message.createResponse(405, 'Method not allowed', None, None, r))
                    return
            else:
                o = self.findTransaction(Transaction.createId(r.first('Via').branch, 'INVITE')) # original transaction
                if not o: 
                    self.send(Message.createResponse(481, "Original transaction does not exist", None, None, r))
                    return
                else:
                    app = o.app
            if app:
                t = Transaction.createServer(self, app, r, self.transport, self.tag)
            elif r.method != 'ACK':
                self.send(Message.createResponse(404, "Not found", None, None, r))
        else:
            t.receivedRequest(r)

    def _receivedResponse(self, r, uri):
        if not r.Via: raise ValueError, 'No Via header in received response'
        branch = r.first('Via').branch
        method = r.CSeq.method
        t = self.findTransaction(Transaction.createId(branch, method))
        if not t:
            if method == 'INVITE' and r.is2xx: # success of INVITE
                d = self.findDialog(r)
                if not d: raise ValueError, 'No transaction or dialog for 2xx of INVITE'
                else: d.receivedResponse(None, r)
            else: raise ValueError, 'No transaction for response'
        else:
            t.receivedResponse(r)

    def findDialog(self, arg):
        return self.dialogs.get(isinstance(arg, Message) and Dialog.extractId(arg) or str(arg), None)

    def findTransaction(self, id):
        return self.transactions.get(id, None)

    def findOtherTransaction(self, r, orig):
        for t in self.transactions.values():
            if t != orig and Transaction.equals(t, r, orig): return t
        return None


    def createServer(self, request, uri, stack): 
        return UserAgent(stack, request) if request.method != "REGISTER" else None

    # def receivedRequest(self, ua, request, stack):
    # def receivedResponse(self, ua, response, stack):
    # def sending(self, ua, message, stack):
    # def cancelled(self, ua, request, stack):
    # def dialogCreated(self, dialog, ua, stack):

    def authenticate(self, ua, obj, stack): 
        obj.username, obj.password = "kundan", "mysecret"
        return True

    def createTimer(self, app, stack): 
        return Timer(app)

class Timer(object):
    def __init__(self, app): self.delay=0; self.app = app;# will invoke app.timedout(self) on timeout
    def start(self, delay=None):
        pass # start the timer
    def stop(self):
        pass # stop the timer