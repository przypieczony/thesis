import re


class URI(object):

	_syntax = re.compile('^(?P<scheme>[a-zA-Z][a-zA-Z0-9\+\-\.]*):' # scheme
	  + '(?:(?:(?P<user>[a-zA-Z0-9\-\_\.\!\~\*\'\(\)&=\+\$,;\?\/\%]+)' # user
	  + '(?::(?P<password>[^:@;\?]+))?)@)?' # password
	  + '(?:(?:(?P<host>[^;\?:]*)(?::(?P<port>[\d]+))?))' # host, port
	  + '(?:;(?P<params>[^\?]*))?' # parameters
	  + '(?:\?(?P<headers>.*))?$') # headers

	def __init__(self, value=''):
		if value:
			m = URI._syntax.match(value)
			if not m: raise ValueError, 'Invalid URI(' + value + ')'
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
				match = regexp.match(value)
			if match:
				self.displayName = match.groups()[0].strip()
				self.uri = URI(match.groups()[1].strip())
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
