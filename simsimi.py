#!/usr/bin/python
#coding=utf-8

import requests


urls = {
    'req'   : r'http://www.simsimi.com/func/req',
    'refer' : r'http://www.simsimi.com/talk.htm',
}

header = {
    'Referer' : urls['refer'],
    'Content-Type' : r'text/html;charset=UTF-8',
    'Uset-Agent' : r'Mozilla/5.0 (Windows NT 6.1; rv:18.0) Gecko/20100101 Firefox/18.0',
}


test_msg = u'今天天气不错哦'

def send(msg = test_msg, lang = 'ch'):
    param = {'lc' : lang, 'msg' : msg}
    cookies = {
        'sagree' : 'true',
        'selected_nc' : lang,
        'JSESSIONID' : '7B6CA482CB2D69DEB3B855418D4D1B54',
    }

    try:
        rSend = requests.get(url = urls['req'], headers = header, cookies = cookies, params = param)
    except:
        print u'发送失败'
        return ''

    if rSend:
        resp = rSend.json()
        return resp.get('response')

if __name__ == '__main__':
    print send()
