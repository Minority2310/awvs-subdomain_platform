#!/usr/bin/env python3
# -*- coding: utf-8 -*-

' AWVS+子域名平台联合自动化渗透测试 '

__author__ = 'Minority'

import requests
from requests.exceptions import Timeout
import json
import urllib3
import hashlib
import time

# 打印响应数据(json格式)
# print(post_result.json())

# 禁止抛出HTTPS错误消息
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# AWVS用户名、密码
username = 'minority2310@163.com'
password = '$WJMINORITY04121313'

# AWVS请求头
headers = {
    'Accept':'application/json, text/javascript, */*; q=0.01',
    'X-Requested-With':'XMLHttpRequest',
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36 Edg/88.0.705.63',
    'Content-Type':'application/json',
    'Origin':'https://192.168.116.132:2310',
    'Referer':'https://192.168.116.132:2310/',
    'RequestValidated':'true',
    'Accept-Language':'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6'
}

# 获取任务域名
def getDomain():

    # 定义变量存放接口地址
    url = "http://d.chinacycc.com/index.php?m=Project&a=ym"
    # 定义变量存放请求体data数据(字典类型)
    data = {
        'type':'python',
        'key':'VIAR9DDS'
    }
    # 定义变量存放请求头headers数据(字典类型)
    headers = {
        'Accept':'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With':'XMLHttpRequest',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36 Edg/88.0.705.56',
        'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept-Language':'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6'
    }
    # 添加代理
    # proxies = {
    #     'http':'192.168.116.1'
    #     'https':'192.168.116.1'
    # }

    # 发送并获取POST请求的结果
    # 添加代理后需要添加proxies=proxies和verify=False(关闭SSL证书检查)
    domains = requests.post(url=url, data=data, headers=headers, timeout=15)

    # 存放域名的列表
    domain_list = []

    # 获取全部域名，返回list类型的值
    for item in domains.json():
        domain_list.append(item['domain'])
    return domain_list

# Hex_MD5加密
def hex_md5(str):
    hex_md5 = hashlib.md5()
    hex_md5.update(str.encode(encoding='utf-8'))
    return hex_md5.hexdigest()

# 登录AWVS
def login():
    # Token格式
    auth = hex_md5(hex_md5(hex_md5(username) + hex_md5(password)) + password)
    data = '{"token":"'+auth+'"}'
    # 登录请求
    result_awvs = requests.post("https://192.168.116.132:2310/api/auth", data=data, headers =headers, timeout=10, verify=False)
    
    # 判断登录是否成功
    if result_awvs.json()['result'] == 'OK':
        # 向headers中添加一个Cookie
        headers['Cookie'] = result_awvs.raw.headers.getlist('Set-Cookie')[0]
        return ("===登录成功!===")
    else:
        return (result_awvs.json()['errorMessage'])

login()

# 添加扫描项目
def addProjects():
    # 获取域名
    domain_list = getDomain()
    # 获取项目id
    id_list = []
    # 当前格式化日期
    current_date = str(time.strftime("%m/%d/%Y", time.localtime()))
    # 扫描格式化日期(当前日期+120秒)
    scan_date = str(time.strftime("%H:%M", time.localtime(time.time()+120)))
    # 循环添加项目
    for domain in domain_list:
        domain = 'http://'+domain+'/'
        data = data = '{"scanType":"scan","targetList":"","target":["'+domain+'"],"recurse":"-1","date":"'+current_date+'","dayOfWeek":"1","dayOfMonth":"1","time":"'+scan_date+'","deleteAfterCompletion":"False","params":{"profile":"Sql_Injection","loginSeq":"<none>","settings":"Default","scanningmode":"heuristic","excludedhours":"<none>","savetodatabase":"True","savelogs":"False","generatereport":"True","reportformat":"HTML","reporttemplate":"WVSDeveloperReport.rep","emailaddress":""}}'
        addProjects = requests.post("https://192.168.116.132:2310/api/addScan", data=data, headers=headers, timeout=15, verify=False)
        id = str(addProjects.json()['data'][0])
        # 判断项目是否添加成功
        if addProjects.json()['result'] == 'OK':
            id_list.append(id)
            print("-->项目添加成功。项目名为：["+domain+"]，项目id为：["+id+"]")
        else:
            print("项目添加失败，请检查!")
    return id_list

# addProjects()
id_list = ['1','2','3','4']

# 获取扫描项目
def getProjects(id_list):
    # 漏洞列表
    bug_list = []

    # 循环请求项目id，获取项目历史信息
    for id in id_list:
        data = '{"id":"'+str(id)+'"}'
        # 请求项目历史信息
        scan_info = requests.post("https://192.168.116.132:2310/api/getScanHistory", data=data, headers=headers, timeout=15, verify=False)
        # 获取项目数据存入列表
        scan_list = scan_info.json()['data']

        # 循环项目数据，返回有漏洞提示信息的项目
        for msg in scan_list:
            # 判断项目数据中是否有漏洞提示信息
            if 'high' in msg['msg'] and '(0 high' not in msg['msg']:
                # 只保留切割前半部分
                url = msg['msg'].split(" =>")[0]
                bug_list.append(id+","+url)
            elif 'medium' in msg['msg'] and ', 0 medium' not in msg['msg']:
                url = msg['msg'].split(" =>")[0]
                bug_list.append(id+","+url)
            elif 'low' in msg['msg'] and ', 0 low' not in msg['msg']:
                url = msg['msg'].split(" =>")[0]
                bug_list.append(id+","+url)
            elif 'info' in msg['msg'] and ', 0 info' not in msg['msg']:
                url = msg['msg'].split(" =>")[0]
                bug_list.append(id+","+url)
    return bug_list

print(getProjects(id_list))