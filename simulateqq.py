#!/usr/bin/python
#coding=utf-8

import os
import sys
import ConfigParser
from hashlib import md5
import re
import requests
from PIL import Image
from StringIO import StringIO
from urllib import urlencode
import time, thread
import random

# 设置字符串编码默认为utf-8
reload(sys)
sys.setdefaultencoding('utf-8')

configFile = '/config.ini'

# 调试级
__DEBUG_LEVEL__ = 1

# api url
urls = {
    'check' : r'https://ssl.ptlogin2.qq.com/check',
    'getvc' : r'https://ssl.captcha.qq.com/getimage',
    'login1' : r'https://ssl.ptlogin2.qq.com/login',
    'login2' : r'http://d.web2.qq.com/channel/login2',
    'poll2' : r'http://d.web2.qq.com/channel/poll2',
    'referer' : r'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=3',
    'getuinfo' : r'http://s.web2.qq.com/api/get_friend_info2',
    'getflist' : r'http://s.web2.qq.com/api/get_user_friends2',
    'getglist' : r'http://s.web2.qq.com/api/get_group_name_list_mask2',
    'sendmsg' : r'http://d.web2.qq.com/channel/send_buddy_msg2',
    'changestatus' : r'http://d.web2.qq.com/channel/change_status2',
    'getfrdqq' : r'http://s.web2.qq.com/api/get_friend_uin2',
}

# 常量参数
aid = '1003903'
r = '0.8833318802393377'
vc_image = './vc.jpeg'
login_status = 'online'
clientid = '10952353'
login_sig = 'zFfQ3BaKy016JIUfYjnL7s*IWLsPnBKfg-xOtfC0JR1D8pzrb0SbDnGvE7LtbKwD'
headers = {
        r'Referer' : urls['referer'],
        r'Content-Type' : r'application/x-www-form-urlencoded; charset=UTF-8',
        r'User-Agent' : r'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:18.0) Gecko/20100101 Firefox/18.0',
        }

# 心跳包发送间隔, 单位为秒
poll_interval = 1 

# 是否使用代理
proxies = {}


def parseConfig(cf):
    __DEBUG_LEVEL__ = cf.getint('setting', 'debug_level')
    poll_interval = cf.getint('setting', 'poll_interval')

    proxies['http'] = cf.get('proxy', 'http')
    proxies['https'] = cf.get('proxy', 'https')


# 打印文档字符串
def printDocString():
    if __DEBUG_LEVEL__:
        print sys._getframe().f_back.f_locals.get('__doc__')

# 获取当前时间戳
def getCurTimeStamp():
    return str(int(time.time() * 1000))

# 转换字符
rawTable = {
        '\n' : r'\\n',
        '\t' : r'\\t',
        '\\' : r'\\',
        '"'  : r'\"',
        }
def convertToRawString(s):
    ret = ''
    for ch in s:
        try:
            ch = rawTable[ch]
        except:
            pass
        finally:
            ret += ch
    return ret

class SimulateQQ:
    
    vc = '' # 验证码
    cookies = {}
    skey = ''
    vfwebqq = ''
    psessionid = 'null'

    curStatus = 'offline'

    user_info = {} # 用户信息
    friend_list = {} # 好友列表
    group_list = {} # 群组列表

    recent_talk_friend = ''


    def __init__(self, user = '', pw = '', s = login_status, cf = None):
        if cf:
            self.uin = cf.get('account', 'qq')
            self.pw = cf.get('account', 'pw')
            s = cf.get('account', 'login_status')

        else:
            self.uin = user
            self.pw = pw

        self.login(s)

    def login(self, status):

        print u'正在登录:%s(%s)' % (self.uin, self.pw)

        self.check()

        if False == self.login1():
            return False

        if False == self.login2(status):
            return False

        # 获取用户信息
        self.getUserInfo()

        # 获取好友列表
        self.getFriendList()

        # 获取群组列表
        self.getGroupList()

        # 开始发送心跳包
        self.startPoll2()

        return True

    # GET
    def get(self, url, params):
        try:
            resp = requests.get(url, params = params, headers = headers, cookies = self.cookies, proxies = proxies)
        except:
            print u'发送失败'
            return 

        self.cookies.update(resp.cookies.get_dict())

        if __DEBUG_LEVEL__:
            print u'===GET请求===，回复:\n%s' % resp.text

        return resp

    # POST
    def post(self, url, data):
        try:
            resp = requests.post(url, data = data, headers = headers, cookies = self.cookies, proxies = proxies)
        except:
            print u'发送失败'
            return 

        self.cookies.update(resp.cookies.get_dict())

        if __DEBUG_LEVEL__:
            print u'===POST请求===，回复:\n%s' % resp.text

        return resp
    
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


    # 解析回复信息
    def parseRespsonse(self, r):
        return re.findall(r"'([^']*)'", r.text)

    # 检查是否要验证码
    def check(self):
        params = {
                    'appid':aid, 
                    'r':r, 
                    'uin':self.uin,
                    'login_sig' : login_sig,
                    'u1' : 'http://web.qq.com/loginproxy.html',
                    'js_type' : '0',
                    'js_ver' : '10015',
                 }

        self.rCheck = self.get(urls['check'], params = params)
        
        resp = self.parseRespsonse(self.rCheck)

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
        self.rGetVC = self.get(urls['getvc'], params = params)
        resp = self.parseRespsonse(self.rGetVC)

        image = Image.open(StringIO(self.rGetVC.content))
        image.save(open(vc_image, 'w'))
        image.show()
        vc = raw_input(u'请输入验证码')
        return vc
        
    # 第一次登录
    def login1(self):
        __doc__ = u'第一次登录...'

        p = self.encodePassword(self.pw, self.uin, self.vc)
        params = {
                'action' : '7-12-32903',
                'aid' : aid,
                'dumy' : '',
                'fp' : 'loginerroralert',
                'from_ui' : '1',
                'g' : '1',
                'h' : '1',
                'js_type' : '0',
                'js_ver' : '10015',
                'login2qq' : '1',
                'login_sig' : r'zFfQ3BaKy016JIUfYjnL7s*IWLsPnBKfg-xOtfC0JR1D8pzrb0SbDnGvE7LtbKwD',
                'mibao_css' : 'm_webqq',
                'p' : p,
                'ptlang' : '2052',
                'ptredirect' : '0',
                'pttype' : '1',
                'remember_uin' : '1',
                't' : '1',
                'u' : self.uin,
                'u1' : r'http://web.qq.com/loginproxy.html?login2qq=1&webqq_type=10',
                'verifycode' : self.vc,
                'webqq_type' : '10'
                }

        if __DEBUG_LEVEL__:
            printDocString()

        self.rLogin1 = self.get(urls['login1'], params = params)
        resp = self.parseRespsonse(self.rLogin1)

        if resp[0] != '0':
            print resp[4]
            return False
        else:
            return True

    # 第二次登录
    def login2(self, status):
        __doc__ = u'第二次登录...'

        r = r'{"status" : "%s", "ptwebqq" : "%s", "passwd_sig" : "", "clientid" : "%s", "psessionid" : null}'  \
                % (status, self.cookies.get("ptwebqq"), clientid)

        data = {
                'clientid' : clientid,
                'psessionid' : 'null',
                'r' : r
                }

        if __DEBUG_LEVEL__:
            printDocString()

        self.rLogin2 = self.post(urls['login2'], data)

        if not self.rLogin2:
            return False

        # 根据返回的状态码判断是否登录成功
        if self.rLogin2.status_code == 200 :

            resp = self.rLogin2.json()
            self.vfwebqq = resp['result']['vfwebqq']
            self.psessionid = resp['result']['psessionid']

            self.curStatus = status

            print '登录成功'

            return True

        else:
            print self.rLogin2.text

            return False

    def parseHeartPkt(self):
        __doc__ = '''解析心跳包'''

        r = self.rPoll2.json()

        # retcode等于0 表示收到特殊的消息
        if 0 == r.get('retcode'):
            printDocString()

            res = r.get('result')
            for item in res:

                poll_type = item.get('poll_type')
                value = item.get('value')

                # 好友状态改变
                if 'buddies_status_change' == poll_type:
                    status = value.get('status')

                    if ('offline' == status) and (self.friend_list.get(i.get('uin'))):
                            del self.friend_list[i.get('uin')]
                    elif 'online' == status:
                        pass

                # 收到好友的信息
                elif 'message' == poll_type:
                    print u'收到消息来自 %s 的消息: ' % value.get('from_uin')
                    print value.get('content')[1]

                    self.recent_talk_friend = value.get('from_uin')


    def _sendHeartPkt(self, data, interval = poll_interval):
        '''发送心跳包'''

        # 根据qq的状态发送心跳包
        while 'offline' != self.curStatus:

            if __DEBUG_LEVEL__ >= 2:
                print u'发送心跳包...'

            self.rPoll2 = self.post(urls['poll2'], data)

            # 发送发生错误的停止发送
            if (self.rPoll2.status_code != 200):

                if __DEBUG_LEVEL__ >= 2:
                    print u'发送心跳包失败，返回：%s' % self.rPoll2.text

                break

            self.parseHeartPkt()

            time.sleep(interval)

        self.curStatus = 'offline'

        print u'下线'
        
    def startPoll2(self):
        '''启动发送心跳包'''

        r = r'{ "ids" : [], "key" : 0, "clientid" : "%s", "psessionid" : "%s" }' \
                % (clientid, self.psessionid)

        data = {
                'clientid' : clientid,
                'psessionid' : self.psessionid,
                'r' : r,
               }

        thread.start_new_thread(self._sendHeartPkt, (data,))

        return True

    def getUserInfo(self, u = ''):
        '''获取用户信息'''

        if u == '':
            u = self.uin

        params = {
                    'tuin' : u,
                    't' : getCurTimeStamp(),
                    'verifysession' : '',
                    'code' : '',
                    'vfwebqq' : self.vfwebqq
                 }
        
        self.rGetUserInfo = self.get(urls['getuinfo'], params = params)
        resp = self.parseRespsonse(self.rGetUserInfo)

        # 解析返回信息
        resp = self.rGetUserInfo.json()
        if resp:
            self.user_info = resp.get('result')
            print resp

        return resp.get('retcode') == 0
    
    def getFriendList(self):
        __doc__ = '''获取好友列表'''

        r = r'{"h":"hello","vfwebqq":"%s"}' % self.vfwebqq

        printDocString()

        self.rGetFrdList = self.post(urls['getflist'], r)

        # 解析返回信息
        resp = self.rGetFrdList.json()
        if resp:
            self.friend_list = resp.get('result')

        return resp.get('retcode') == 0

    def getGroupList(self):
        __doc__ = '''获取群组列表'''

        r = r'{"vfwebqq":"%s"}' % self.vfwebqq

        printDocString()

        self.rGetGrpList = self.post(urls['getglist'], r)

        # 解析返回信息
        resp = self.rGetGrpList.json()
        self.group_list = resp.get('result')

        return resp.get('retcode') == 0

    # 下线
    def offline(self):
        self.changeStatus('offline')

    # 根据uin用户的qq号
    def getFriendAccount(self, tuin):
        params = {
                    'code' : '',
                    't' : getCurTimeStamp(),
                    'tuin' : tuin,
                    'verifysession' : '',
                    'vfwebqq' : self.vfwebqq
                 }

        self.rGetFrdQQ = self.get(urls['getfrdqq'], params = params)
        resp = self.rGetFrdQQ.json()

        qq = ''
        if resp and resp.get('result'):
            qq = str(resp.get('result').get('account'))

        return qq 

    def reply(self):
        return self.sendMsg(to = self.recent_talk_friend)

    def sendMsg(self, to, msg = u'', msg_id = random.randrange(start=9999999)):
        __doc__ = '''发送信息'''

        if not to:
            return False
    
        if msg == u'':
            while True:
                s = raw_input("Send Message >> ")
                if s == '':
                    break

                msg += s + '\n'

            if msg == u'':
                return True

        msg = convertToRawString(msg)

        r = ur'{"to":%s,"content":"[\"%s\",[\"font\",{\"name\":\"宋体\",\"size\":\"10\",\"style\":[0,0,0],\"color\":\"000000\"}]]","msg_id":%s,"clientid":"%s", "psessionid":"%s"}'  \
            % (to, msg, msg_id, clientid, self.psessionid)

        data = {
                    'clientid' : clientid,
                    'psessionid' : self.psessionid,
                    'r' : r
               }

        printDocString()

        self.rsendmsg = self.post(urls['sendmsg'], data)
        if not self.rsendmsg:
            return False

        resp = self.rsendmsg.json()

        print resp.get('result')

        return 0 == resp.get('retcode')

    def changeStatus(self, s):
        __doc__ = '''修改在线状态'''

        if s == self.curStatus:
            return True

        params = {
                    'clientid' : clientid,
                    'newstatus' : s,
                    'psessionid' : self.psessionid,
                    't' : getCurTimeStamp()
                 }

        self.rChangeStatus = self.get(urls['changestatus'], params = params)
        if not self.rChangeStatus:
            return False

        resp = self.rChangeStatus.json()
        print resp.get('result')

        if 0 == resp.get('retcode'):
            self.curStatus = s

            if 'online' == s:
                return self.login()

            return True

        return False


if __name__ == '__main__':
    cf = ConfigParser.ConfigParser()

    cf.read(os.getenv('HOME') + configFile)
    parseConfig(cf)

    qq = SimulateQQ(cf = cf)
