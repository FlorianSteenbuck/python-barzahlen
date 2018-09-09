import hashlib
import json
import urlparse
import hmac
import time
import datetime
import random
import math

from hashlib import sha256

from requests import Request as RRequest
# TODO find a oop solution without session
from requests import Session as RSession

from threading import Thread, Lock

MAX_RAND_NUMBER = 9000000000

def rand(min=0, max=MAX_RAND_NUMBER):
    return random.randint(min, max)

def uniqid(prefix='', more_entropy=False):
    """uniqid([prefix=''[, more_entropy=False]]) -> str
    Gets a prefixed unique identifier based on the current
    time in microseconds.
    prefix
        Can be useful, for instance, if you generate identifiers
        simultaneously on several hosts that might happen to generate
        the identifier at the same microsecond.
        With an empty prefix, the returned string will be 13 characters
        long. If more_entropy is True, it will be 23 characters.
    more_entropy
        If set to True, uniqid() will add additional entropy (using
        the combined linear congruential generator) at the end of
        the return value, which increases the likelihood that
        the result will be unique.
    Returns the unique identifier, as a string."""
    m = time.time()
    sec = math.floor(m)
    usec = math.floor(1000000 * (m - sec))
    if more_entropy:
        lcg = random.random()
        the_uniqid = "%08x%05x%.8F" % (sec, usec, lcg * 10)
    else:
        the_uniqid = '%8x%05x' % (sec, usec)

    the_uniqid = str(prefix) + str(the_uniqid)
    return the_uniqid

def httpdate(dt):
    """Return a string representation of a date according to RFC 1123
    (HTTP/1.1).

    The supplied date must be in UTC.

    """
    weekday = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][dt.weekday()]
    month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
             "Oct", "Nov", "Dec"][dt.month - 1]
    return "%s, %02d %s %04d %02d:%02d:%02d GMT" % (weekday, dt.day, month,
        dt.year, dt.hour, dt.minute, dt.second)

def hash_hmac(algo, data, key):
    print data
    res = hmac.new(key, data, getattr(hashlib, algo)).hexdigest()
    return res

def md5(s, raw_output=False):
    """Calculates the md5 hash of a given string"""
    res = hashlib.md5(s.encode())
    if raw_output:
        return res.digest()
    return res.hexdigest()

def hash(algo, data):
    return getattr(hashlib, algo)(data).hexdigest()

def substr(s, start, length=None):
    """Returns the portion of string specified by the start and length 
    parameters.
    """
    if len(s) >= start:
        if start > 0:
            return False
        else:
            return s[start:]
    if not length:
        return s[start:]
    elif length > 0:
        return s[start:start + length]
    else:
        return s[start:length]

def parse_url(url, key):
    results = urlparse.urlparse(url)
    result = getattr(results, key, None)
    if result == None:
        result = ""
    return result

class ApiException(Exception):
    _requestId = None

    def __init__(self, message, requestId='N/A'):
        super(Exception, self).__init__(message)
        self.requestId = requestId

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return self.__class__.__name__ + ": "+self.message+" - RequestId: "+self.requestId+""

class AuthException(ApiException):
    pass

class CurlException(ApiException):
    pass

class IdempotencyException(ApiException):
    pass

class InvalidFormatException(ApiException):
    pass

class InvalidParameterException(ApiException):
    pass

class InvalidStateException(ApiException):
    pass

class NotAllowedException(ApiException):
    pass

class RateLimitException(ApiException):
    pass

class ServerException(ApiException):
    pass

class TransportException(ApiException):
    pass

class Middleware():
    @staticmethod
    def generateSignature(host, method, path, query, date, idempotency, body, key):
        signatureData = [
            host,
            method,
            path,
            query,
            date,
            idempotency,
            hash('sha256', body)
        ]
        signatureString = "\n".join(signatureData)
        return hash_hmac('sha256', signatureString, key)

    @staticmethod    
    def stringEquals(first, second):
        if len(first) != len(second):
            return False

        res = first ^ second
        ret = 0
        i = len(res) - 1
        while i >= 0:
            ret |= ord(res[i])
            i-=1
        return not ret

    @staticmethod    
    def stringIsPrefix(prefix, string):
        return substr(string, 0, len(prefix)) == prefix

class Client():
    API_URL = 'https://api.barzahlen.de:443/v2'
    API_SANDBOX_URL = 'https://api-sandbox.barzahlen.de:443/v2'

    __divisionId = None
    __paymentKey = None
    __apiUrl = None
    __userAgent = 'Python SDK v1.0.0'

    def __init__(self, divisionId, paymentKey, sandbox=False):
        self.__divisionId = divisionId
        self.__paymentKey = paymentKey
        self.__apiUrl = self.API_SANDBOX_URL
        if not sandbox:
            self.__apiUrl = self.API_URL
    
    def setUserAgent(self, userAgent):
        self.userAgent = userAgent
        return self

    def handle(self, request):
        session = RSession()
        url = self.__apiUrl + request.getPath()

        req = RRequest(request.getMethod(), url, headers=self.buildHeader(request))
        prepped = req.prepare()
        prepped.body = request.getBody()
        
        resp = session.send(prepped, verify=True)
        json_resp = None
        try:
            json_resp = json.loads(resp.content)
        except:
            pass

        self.checkResponse(json_resp, resp.headers["content-type"])

        return json_resp

    def buildHeader(self, request):
        date = httpdate(datetime.datetime.utcnow())
        idempotencyKey = ''
        if request.getIdempotence():
            idempotencyKey = md5(uniqid(rand(), True))

        signature = Middleware.generateSignature(
            parse_url(self.__apiUrl, "hostname") + ':' + str(parse_url(self.__apiUrl, "port")),
            request.getMethod(),
            parse_url(self.__apiUrl + request.getPath(), "path"),
            parse_url(self.__apiUrl, "query"),
            date,
            idempotencyKey,
            request.getBody(),
            self.__paymentKey
        )

        header = {
            "Host": parse_url(self.__apiUrl, "hostname"),
            "Date": date,
            "User-Agent":  self.__userAgent,
            "Authorization": "BZ1-HMAC-SHA256 DivisionId=" + self.__divisionId + ", Signature=" + signature
        }

        if idempotencyKey != '':
            header["Idempotency-Key"] = idempotencyKey

        return header

    def checkResponse(self, response, contentType):
        if Middleware.stringIsPrefix('application/json', contentType):
            if strpos(response, 'error_class') == False:
                return

            response = json.loads(response)
            errorMapping = {
                'auth': AuthException,
                'transport': TransportException,
                'idempotency': IdempotencyException,
                'rate_limit': RateLimitException,
                'invalid_format': InvalidFormatException,
                'invalid_state': InvalidStateException,
                'invalid_parameter': InvalidParameterException,
                'not_allowed': NotAllowedException,
                'server_error': ServerException
               }

            if response.error_class in errorMapping:
                raise errorMapping[response.error_class](response.message, response.request_id)

            raise ApiException(response.message, response.request_id)

class Webhook():
    # TODO porting to python
    # currently not needed
    pass

class Request():
    _idempotence = False
    _path = ''
    _parameters = []
    _method = ''

    def getIdempotence(self):
        return self._idempotence
    
    def getPath(self):
        return self._path % tuple(self._parameters)

    def getMethod(self):
        return self._method

    def getBody(self):
        return None

class CreateRequest(Request):
    _idempotence = True
    _path = '/slips'
    _method = 'POST'
    _body = None

    __slipType = None
    __forSlipId = None
    __referenceKey = None
    __hookUrl = None
    __expiresAt = None
    __customer = {}
    __address = None
    __transactions = []
    __metadata = {}
    
    def setBody(self, body):
        if type(body) == dict or type(body) == list:
            self._body = json.dumps(body)
        else:
            self._body = body
        return self

    def setSlipType(self, slipType):
        self.__slipType = slipType
        return self
    
    def setForSlipId(self, forSlipId):
        self.__forSlipId = forSlipId
        return self
    
    def setReferenceKey(self, referenceKey):
        self.__referenceKey = referenceKey
        return self
    
    def setHookUrl(self, hookUrl):
        self.__hookUrl = hookUrl
        return self
    
    def setExpiresAt(self, expiresAt):
        if isinstance(expiresAt, datetime.datetime):
            self.__expiresAt = expiresAt.isoformat()
        else:
            self.__expiresAt = expiresAt
        return self

    def setCustomer(self, customer):
        self.__customer = customer
        return self
    
    def setCustomerKey(self, customerKey):
        self.__customer['key'] = customerKey
        return self
    
    def setCustomerCellPhone(self, customerCellPhone):
        self.__customer['cell_phone'] = customerCellPhone
        return self
    
    def setCustomerEmail(self, customerEmail):
        self.__customer['email'] = customerEmail
        return self

    def setCustomerLanguage(self, customerLanguage):
        self.__customer['language'] = customerLanguage
        return self

    def setAddress(self, address):
        self.__address = address
        return self
    
    def setTransaction(self, amount, currency='EUR'):
        if len(self.__transactions) <= 0:
            self.__transactions.append(None) 
        self.__transactions[0] = {
            'amount': amount,
            'currency': currency
        }
        return self
    
    def setAmount(self, amount):
        if len(self.__transactions) <= 0:
            self.__transactions.append(None) 
        self.__transactions[0]['amount'] = amount
        return self
    
    def setCurrency(self, currency):
        if len(self.__transactions) <= 0:
            self.__transactions.append(None) 
        self.__transactions[0]['currency'] = currency
        return self
    
    def addMetadata(self, key, value):
        self.__metadata[key] = value
        return self
    
    def getBody(self):
        if self._body is not None:
            return self._body

        body = {
            'slip_type': self.__slipType,
            'transactions': self.__transactions
           }

        if len(self.__customer) > 0:
            body['customer'] = self.__customer

        if self.__forSlipId and self.__slipType == 'refund':
            body['refund'] = {'for_slip_id': self.__forSlipId}

        if self.__referenceKey:
            body['reference_key'] = self.__referenceKey

        if self.__hookUrl:
            body['hook_url'] = self.__hookUrl

        if self.__expiresAt:
            body['expires_at'] = self.__expiresAt

        if self.__address:
            body['show_stores_near'] = {'address': self.__address}

        if len(self.__metadata) > 0:
            body['metadata'] = self.__metadata

        return json.dumps(body)

class InvalidateRequest(Request):
    _path = '/slips/%s/invalidate'
    _method = 'POST'

    def __init__(self, slipId):
        self._parameters.append(slipId)

class ResendRequest(Request):
    _path = '/slips/%s/resend/%s'
    _method = 'POST'

    def __init__(self, slipId, typ):
        self._parameters.append(slipId)
        self._parameters.append(typ)

class RetrievePdfRequest(Request):
    _path = '/slips/%s/media/pdf'
    _method = 'GET'

    def __init__(self, slipId):
        self._parameters.append(slipId)

class RetrieveRequest(Request):
    _path = '/slips/%s'
    _method = 'GET'

    def __init__(self, slipId):
        self._parameters.append(slipId)

class UpdateRequest(Request):
    _path = '/slips/%s'
    _method = 'PATCH'
    _body = None

    __customer = {}
    __expiresAt = None
    __referenceKey = None   
    __transactions = []

    def __init__(self, slipId):
        self._parameters.append(slipId)

    def setBody(self, body):
        if type(body) == dict or type(body) == list:
            self.__body = json.dumps(body)
        else:
            self.__body = body
        return self

    def setCustomer(self, customer):
        self.__customer = customer
        return self

    def setCustomerCellPhone(self, customerCellPhone):
        self.__customer['cell_phone'] = customerCellPhone

        return self
    def setCustomerEmail(self, customerEmail):
        self.__customer['email'] = customerEmail

        return self
    def setExpiresAt(self, expiresAt):
        if isinstance(expiresAt, datetime.datetime):
            self.__expiresAt = expiresAt.isoformat()
        else:
            self.__expiresAt = expiresAt
   
        return self
    def setReferenceKey(self, referenceKey):
        self.__referenceKey = referenceKey
        return self

    def setTransaction(self, _id, amount):
        if len(self.__transactions) <= 0:
            self.__transactions.append(None) 
        self.__transactions[0] = {
            'id': _id,
            'amount': amount
        }

        return self
    def setTransactionId(self, transactionId):
        if len(self.__transactions) <= 0:
            self.__transactions.append(None) 
        self.__transactions[0]['id'] = transactionId

        return self
    def setAmount(self, amount):
        if len(self.__transactions) <= 0:
            self.__transactions.append(None) 
        self.__transactions[0]['amount'] = amount
        return self

    def getBody(self):
        if self._body is not None:
            return self._body
   
        body = {}

        if len(self.__customer) > 0:
            body['customer'] = self.__customer
   
        if self.__expiresAt:
            body['expires_at'] = self.__expiresAt
   
        if self.__referenceKey:
            body['reference_key'] = self.__referenceKey
   
        if len(self.__transactions) > 0:
            body['transactions'] = self.__transactions
  
        return json.dumps(body)

# simple api
# TODO test

CLIENT = None

RATE_LIMIT_BLOCK = False
RATE_LIMIT_LOCK = Lock()
RATE_LIMIT_EXTRAS = 0
RATE_LIMIT_WAIT = 10
RATE_LIMIT_WAIT_EXTRA = 5

def __rate_limit_thread__():
	RATE_LIMIT_LOCK.acquire()	
	RATE_LIMIT_BLOCK = True
	time.sleep(10)
	while RATE_LIMIT_EXTRAS > 0:
		time.sleep(5)
		RATE_LIMIT_EXTRAS-=1
	RATE_LIMIT_BLOCK = False
	RATE_LIMIT_LOCK.release()

def configure(divisionId, paymentKey, sandbox=False, rate_limit_wait=10, rate_limit_wait_extra=5):
	CLIENT = Client(divisionId, paymentKey, sandbox)
	RATE_LIMIT_WAIT = rate_limit_wait
	RATE_LIMIT_WAIT_EXTRA = rate_limit_wait_extra

supported_currencies = ["EUR","USD"]

def currency_to_currency_value(currency):
	return currency.upper()

def amount_to_value(value, currency):
	return value

def __rate_limit_acquire__():
	if RATE_LIMIT_BLOCK:
		return False, RateLimitException('We kill the limits and currently waiting for a new limit to be appeared')

def __rate_limit_handle__(request):
	try:
		return True, CLIENT.handle(request)
	except RateLimitException, ex:
		if RATE_LIMIT_BLOCK:
			RATE_LIMIT_EXTRAS+=1
		else:
			Thread(target=__rate_limit_thread__).start()
		return False, ex
	except ApiException, ex:
		return False, ex

def charge(value, currency, email=None, customer_key=None):
	__rate_limit_acquire__()
    if email == None  and customer_key == None:
        raise False, InvalidParameterException("We need a id or email for the customer without a id or email we can not use the barzahlen api")
	request = CreateRequest()
	request.setSlipType('payment')
    if customer_key == None:
	   request.setCustomerKey(email)
	else:
        request.setCustomerKey(customer_key)
    if email != None:
        request.setCustomerEmail(email)
	request.setTransaction(value, currency)
	success, resp = __rate_limit_handle__(request)
	if not success:
		return False, resp
	return True, resp

def valid_charge(resp, value, currency):
	__rate_limit_acquire__()
	request = RetrieveRequest()
	request.setForSlipId(resp['id'])
	success, resp = __rate_limit_handle__(request)
	if not success:
		return False, False
	
	paid = True
	actual_value = 0
	for transaction in resp["transactions"]:
		if transaction["state"] is not "paid" or transaction["currency"] is not currency:
			paid = False
			break
		actual_value += transaction["amount"]

	return True, paid and actual_value == value