#!/usr/bin/python
#coding=utf-8

from md5 import md5
import re
import requests
from PIL import Image
from StringIO import StringIO
from urllib import urlencode
import time, thread

# 调试级
__DEBUG_LEVEL__ = 2

aid = '1003903'
r = '0.8833318802393377'
urls = {
    'check' : r'https://ssl.ptlogin2.qq.com/check',
    'getvc' : r'https://ssl.captcha.qq.com/getimage',
    'login1' : r'https://ssl.ptlogin2.qq.com/login',
    'login2' : r'http://d.web2.qq.com/channel/login2',
    'poll2' : r'http://d.web2.qq.com/channel/poll2',
    'referer' : r'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=3',
}

vc_image = './vc.jpeg'
login_status = 'hidden'
clientid = '10952353'

headers = {
        r'Referer' : urls['referer'],
        r'Content-Type' : r'application/x-www-form-urlencoded; charset=UTF-8',
        r'User-Agent' : r'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:18.0) Gecko/20100101 Firefox/18.0',
        }

class SimulateQQ:
    
    verifycode = '' # 验证码
    cookies = {}
    skey = ''
    vfwebqq = ''
    psessionid = 'null'

    cur_status = 'offline'

    def __init__(self, user = '1147285955', pw = ''):
        self.uin = user
        self.pw = pw

    def login(self):
        self.check()

        if False == self.login1():
            return False

        if False == self.login2():
            return False

        self.poll2()


    # GET
    def get(self, url, params):
        resp = requests.get(url, params = params, cookies = self.cookies)
        self.cookies.update(resp.cookies.get_dict())

        if __DEBUG_LEVEL__ >= 2:
            print u'===GET请求===，回复:\n%s' % resp.text

        return (resp, self.parse_response(resp))

    # POST
    def post(self, url, data):
        resp = requests.post(url, data = data, headers = headers, cookies = self.cookies)
        self.cookies.update(resp.cookies.get_dict())

        if __DEBUG_LEVEL__ >= 2:
            print u'===POST请求===，回复:\n%s' % resp.text

        return resp
    
    # 解析回复信息
    def parse_response(self, r):
        return re.findall(r"'([^']*)'", r.text)

    # 检查是否要验证码
    def check(self):
        params = {'appid':aid, 'r':r, 'uin':self.uin}
        self.rcheck, resp = self.get(urls['check'], params = params)

        # 0:不用验证码， 1:要验证码
        if resp[0] == '0':
            self.vc = resp[1]
        else:
            self.vc = self.getvc()

        if __DEBUG_LEVEL__:
            print u'验证码为', self.vc
            
    # 获取验证码图片
    def getvc(self):
        params = {'aid':aid, 'r':r, 'uin':uin}
        self.rgetvc, resp = self.get(urls['getvc'], params = params)

        image = Image.open(StringIO(self.rgetvc.content))
        image.save(open(vc_image, 'w'))
        image.show()
        vc = raw_input(u'请输入验证码')
        return vc
        
    # 第一次登录
    def login1(self):
        login_success = u'登录成功！'
        p = self.encodePassword(self.pw, self.uin, self.vc)
        params = {
                'aid' : aid,
                'from_ui' : '1',
                'g' : '1',
                'h' : '1',
                'login2qq' : '1',
                'login_sig' : r'zFfQ3BaKy016JIUfYjnL7s*IWLsPnBKfg-xOtfC0JR1D8pzrb0SbDnGvE7LtbKwD',
                'p' : p,
                'ptlang' : '2052',
                'ptredirect' : '0',
                'pttype' : '1',
                'remember_uin' : '1',
                't' : '1',
                'u' : self.uin,
                'u1' : r'http://web.qq.com/loginproxy.html?login2qq=1&webqq_type=10',
                'verifycode' : self.vc,
                }

        self.rlogin1, resp = self.get(urls['login1'], params = params)

        print resp[4]

        return resp[4] == login_success

    # 第二次登录
    def login2(self, psessionid = 'null'):
        r = r'{"status" : "%s", "ptwebqq" : "%s", "passwd_sig" : "", "clientid" : "%s", "psessionid" : %s}'  \
                % (login_status, self.cookies.get("ptwebqq"), clientid, psessionid)

        data = {
                'clientid' : clientid,
                'psessionid' : psessionid,
                'r' : r
                }

        self.rlogin2 = self.post(urls['login2'], data)
        resp = self.rlogin2.json()

        # 根据返回的状态码判断是否登录成功
        if self.rlogin2.status_code == 200 :

            self.vfwebqq = resp['result']['vfwebqq']
            self.psessionid = resp['result']['psessionid']

            self.cur_status = login_status

            return True

        else:
            print self.rlogin2.text

            return False

    # 发送心跳包
    def sendHeartPkt(self, data, interval):

        # 根据qq的状态发送心跳包
        while 'offline' != self.cur_status:

            if __DEBUG_LEVEL__ >= 2:
                print u'发送心跳包...'

            self.rpoll2 = self.post(urls['poll2'], data)

            # 发送发生错误的停止发送
            if (self.rpoll2.status_code != 200):

                if __DEBUG_LEVEL__ >= 2:
                    print u'发送心跳包失败，返回：%s' % self.rpoll2.text

                break

            time.sleep(interval)

        self.cur_status = 'offline'

        print u'下线'
        
    # 启动发送心跳包
    def poll2(self):
        r = r'{ "ids" : [], "key" : 0, "clientid" : "%s", "psessionid" : "%s" }' \
                % (clientid, self.psessionid)

        data = {
                'clientid' : clientid,
                'psessionid' : self.psessionid,
                'r' : r,
               }

        thread.start_new_thread(self.sendHeartPkt, (data, 2))

        return True

    # 下线
    def offline(self):
        self.cur_status = 'offline'

    # 对密码做转换
    def encodePassword(self, pw, uin, verifycode):

        # Insert '\x'
        def hexchar2bin(s):
            return (''.join([ chr(int(i, 16)) for i in re.findall('.{1,2}', s) ]))

        def mymd5(s):
            return md5(s).hexdigest().upper()

        def uin2hex(uin):
            maxlen = 16

            # parse number in front
            uin = re.match('^[0-9]*', uin).group()

            # convert to hex
            uin = str(hex(int(uin, 10)))[2:]

            uin = uin[:maxlen]
            uin = (maxlen - len(uin)) * '0' + uin

            return hexchar2bin(uin)

        ret = hexchar2bin(mymd5(pw)) 
        ret = mymd5(ret + uin2hex(uin))
        ret = mymd5(ret + verifycode.upper())
        return ret

if __name__ == '__main__':
    pass
