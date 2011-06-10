#!/usr/bin/python

SAVE_SHARES = True

import os, os.path
import hashlib
import struct
import socket
import threading
from base64 import b64encode
import base64
import httplib
import json
import time
import sys

settings = {
    'host':'',
    'port':8332,
    'rpcuser':'',
    'rpcpass':''
}

if not sys.argv[1:]:
    print 'arguments are required:'
    print '-u username --pass pwd -o host -p port'
    exit()

mode = None
bad_args = False
for arg in sys.argv[1:]:
    if arg in ('-u', '-p', '--pass', '-o'):
        mode = arg
    elif mode:
        if mode == '-u':
            settings['rpcuser'] = arg
        if mode == '-p':
            settings['port'] = arg
        if mode == '--pass':
            settings['rpcpass'] = arg
        if mode == '-o':
            settings['host'] = arg
        mode = None
    else:
        bad_args = True

if bad_args:
    print 'arguments are possibly invalid. starting up anyway'

del mode



clients = []



class Printer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.done = False
        self.line = []
        self.start()
    def say(self, *what):
        self.line.append(' '.join([str(s) for s in what]))
        while self.line:
            time.sleep(0.01)
    def run(self):
        while not self.done:
            time.sleep(0.01)
            while self.line:
                print self.line.pop(0)
printer = Printer()


class ClientListener(threading.Thread):
    def __init__(self, host='', port=15063):
        self.timeout = 5
        self.host = host
        self.port = port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.new_clients = []
        self.done = False
        threading.Thread.__init__(self)
    
    def get_new_clients(self):
        nc, self.new_clients = self.new_clients, []
        return nc
    
    def stop(self):
        self.done = True
    
    def run(self):
        try:
            s = self.s
            s.bind((self.host,self.port))
            printer.say('initializing client listener')
            while not self.done:
                s.settimeout(self.timeout)
                timeout = False
                try:
                    s.listen(1)
                    conn, addr = s.accept()
                except socket.timeout:
                    timeout = True
                if not timeout:
                    printer.say( 'new client!', addr)
                    conn.setblocking(0)
                    self.new_clients.append((conn,addr))
        except:
            self.done = True
            s.close()
            raise

class WorkManager(threading.Thread):
    def __init__(self):
        self.need_update = False
        self.manage_delay = 0.5
        self.cur_work = None
        self.clients = []
        self.got = []
        cl = self.client_listener = ClientListener()
        cl.start()
        self.done = False
        threading.Thread.__init__(self)
    
    def set_work(self, data, target):
        if data + target != self.cur_work:
            self.cur_work = data + target
            self.work_data = data
            self.work_target = target
            self.need_update = True
    
    def send_work(self, client):
        try:
            if self.cur_work is not None:
                client[0].send(self.cur_work+'\n')
                if client[2] == 'init':
                    client[2] == 'work sent'
        except socket.error, e:
            if e.errno == 11: # socket isn't ready
                pass
            elif e.errno in (32, 104, 110): # 110 is timeout
                printer.say('removing client',client[1])
                self.clients.remove(client)
            else:
                printer.say('strange error while trying to send work')
                raise
    
    def init_client(self, client):
        c = client
        if len(c) < 6:
            c = [c[0], c[1], 'init', '', '', 0]
        else:
            c[2] == 'init'
        self.send_work(c)
        return c
    
    def run(self):
        try:
            printer.say('initializing work manager')
            while not self.done:
                time.sleep(self.manage_delay)
                if self.client_listener.done:
                    self.done = True
                
                # initialize new clients
                cl = self.client_listener
                cl_nc = cl.new_clients
                if cl_nc:
                    nc = cl.get_new_clients()
                    for c in nc:
                        c = self.init_client(c)
                        self.clients.append(c)
                
                # see if there's anything new
                for c in self.clients[:]:
                    try:
                        got = c[0].recv(1024)
                        if got:
                            printer.say('GOT SOMETHING!',repr(got))
                            c[3] = c[3] + got
                        csplit = c[3].split('\n')
                        for piece in csplit[:-1]:
                            if piece[-1] == '\r': piece = piece[:-1]
                            if len(piece) == 8:
                                # it's (probably) a nonce! :O
                                ishex = True
                                for ch in piece:
                                    if ch not in '0123456789abcdefABCDEF':
                                        ishex = False
                                        break
                                if ishex:
                                    self.got.append((struct.unpack('<I', piece.decode('hex'))[0], c))
                            elif piece.startswith('http://'):
                                # this could be used to differentiate
                                # between different accounts, if you
                                # made this into an embeddable service thing
                                if '?sendto=' in piece:
                                    st = piece.split('?sendto=')
                                    good_sendto = True
                                    for pchar in st[-1]:
                                        if pchar not in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz':
                                            good_sendto = False
                                            break
                                    if good_sendto and 35 > len(st[-1]) > 24:
                                        c[4] = st[-1]
                                #else:
                                #    c[4] = piece
                            else:
                                # probably unsupported features or somebody sending random data trying to break stuff
                                printer.say('...but the thing I got is weird!')
                        # stuff the end back in in case we got a partial message
                        c[3] = csplit[-1]
                    except socket.error, e:
                        if e.errno == 11: # socket isn't ready
                            pass
                        elif e.errno in (32,104,110): # client left,110=timeout
                            printer.say('removing client',c[1])
                            self.clients.remove(c)
                        else: # a strange and mysterious occurence
                            printer.say('client socket error')
                            raise
                
                # send out new work if there is any
                if self.need_update:
                    self.need_update = False
                    for c in self.clients[:]:
                        self.send_work(c)
            self.client_listener.stop()
            self.done = True
        except:
            # shutdown the client listener first so we can go down cleanly
            self.done = True
            self.client_listener.stop()
            raise


def bytereverse(x):
    return 0xffffffffL & (( ((x) << 24) | (((x) << 8) & 0x00ff0000) | (((x) >> 8) & 0x0000ff00) | ((x) >> 24) ))
def bufreverse(in_buf):
    out_words = []
    for i in range(0, len(in_buf), 4):
        word = struct.unpack('@I', in_buf[i:i+4])[0]
        out_words.append(struct.pack('@I', bytereverse(word)))
    return ''.join(out_words)
def wordreverse(in_buf):
    out_words = []
    for i in range(0, len(in_buf), 4):
        out_words.append(in_buf[i:i+4])
    out_words.reverse()
    return ''.join(out_words)


class BitcoinRPC(object):
    OID = 1
    def __init__(self, host, port, username, password):
        authpair = "%s:%s" % (username, password)
        self.authhdr = "Basic %s" % (base64.b64encode(authpair))
        self.conn = httplib.HTTPConnection(host, port, False, 30)
        printer.say('initializing rpc')
    
    def rpc(self, method, params=None):
        headers = {'Authorization':self.authhdr,'Content-type':'application/json'}
        self.OID += 1
        obj = {'version':'1.1','method':method,'id':self.OID}
        obj['params'] = ((params is None) and ([],) or (params,))[0]
        badresp = False
        try:
            self.conn.request('POST','/',json.dumps(obj),headers)
            resp = self.conn.getresponse()
        except Exception, e:
            badresp = True
            print e
        if badresp:
            printer.say('rpc got a bad response')
            return None
        if resp is None:
            printer.say('no response from rpc')
            return None

        if resp.status == httplib.UNAUTHORIZED: raise NotAuthorized()

        # something strange happened. it is a mystery within an enigma
        if str(resp.status) != '200':
            printer.say('weird response status:',resp.status)

        rjson = json.loads(resp.read())
        if rjson is None or 'result' not in rjson:
            printer.say("rpc's response was invalid")
            return None
        if 'error' in rjson and rjson['error'] is not None:
            printer.say('some sort of rpc error occurred...')
            return rjson['error']
        return rjson['result']
    
    def getwork(self, data=None):
        return self.rpc('getwork', data)


class Miner(object):
    def __init__(self):
        self.rpc = None
        self.done = False
        # a higher value might better here...?
        # anything older than the number of seconds
        # here is considered invalid/stale
        self.manage_interval = 5
        self.work_manager = WorkManager()
        self.work_manager.start()

    def check_work(self, datastr, targetstr, nonce, byteswap=False):
        target = long(targetstr.decode('hex')[::-1].encode('hex'), 16)
        if not byteswap: nonce_bin = struct.pack('<I', nonce)
        else: nonce_bin = struct.pack('>I', nonce)
        hash = hashlib.sha256()
        hash.update(bufreverse(datastr.decode('hex'))[:76])
        hash.update(nonce_bin)
        hash_o = hashlib.sha256()
        hash_o.update(hash.digest())
        hash = hash_o.digest()
        # do the basic 0x00000000 ending test
        if not hash.endswith('\x00\x00\x00\x00'):
            if not byteswap:
                return self.check_work(datastr, targetstr, nonce, True)
            return False, nonce_bin
        return long(wordreverse(bufreverse(hash)).encode('hex'), 16) < target, nonce_bin

    def submit_work(self, rpc, original_data, nonce_bin, who):
        result = rpc.getwork([original_data[:152] + bufreverse(nonce_bin).encode('hex') + original_data[160:256]])
        printer.say("result accepted?", repr(result))
        if result == True:
            who[5] += 1
            if SAVE_SHARES and who[4]:
                if not os.path.exists('shares/'+who[4]+'/'):
                    os.makedirs('shares/'+who[4]+'/')
                f = open('shares/'+who[4]+'/'+str(time.time()), 'wb')
                f.write('\n')
                f.close()

    def dowork(self):
        rpc = self.rpc
        if self.work_manager.done:
            self.done = True
            return

        got = []
        if self.work_manager.got:
            got, self.work_manager.got = self.work_manager.got, []
            wdata = self.work_manager.work_data
            wtarget = self.work_manager.work_target
        
        for nonce, who in got:
            is_good, nonce_bin = self.check_work(wdata,wtarget, nonce)
            if is_good:
                printer.say('sending good data')
                self.submit_work(rpc, wdata, nonce_bin, who)
            else:
                printer.say('data was bad')
        
        work = rpc.getwork()
        if work is None or 'data' not in work or 'target' not in work:
            return
        
        self.work_manager.set_work(work['data'], work['target'])

    def loop(self):
        self.rpc = BitcoinRPC(settings['host'],settings['port'],settings['rpcuser'],settings['rpcpass'])
        while not self.done:
            time.sleep(self.manage_interval)
            self.dowork()



try:
    printer.say('Starting up. Use ctrl+c to exit.')
    miner = Miner()
    miner.loop()
except KeyboardInterrupt:
    pass
except:
    miner.work_manager.done = True
    printer.done = True
    raise

miner.work_manager.done = True
printer.done = True
