所使用的cms为Free and Open Source inventory management system，网址为[Free and Open Source inventory management system php source code | SourceCodester](https://www.sourcecodester.com/php/16741/free-and-open-source-inventory-management-system-php-source-code.html)，发现的漏洞为基于盲注的sql注入漏洞，首先将搭建环境，然后手动测试验证该漏洞存在，再使用sqlmap验证该漏洞存在



### 1.搭建环境

下载完cms的压缩包之后，将php源码解压出来放在网站目录下，再按照搭建说明创建一个名为ample的mysql数据库，然后导入 ample/database/ample.sql文件，创建所需的数据表，再修改配置文件ample\app\config\config.php,将数据库名称和数据库用户名密码设置好。完成了之后访问该网站，出现以下页面且无数据库报错说明环境配置成功（从数据库中可以看到默认的用户名为mayuri.infospace@gmail.com，密码为admin，数据库存储的是密码的哈希值）

![image-20230814204907264](.\images\image-20230814204907264.png)

### 2.手动验证

进入到http://ample/index.php?page=member页面之后，可以看到该页面用于显示顾客信息

![image-20230814212223335](.\images\image-20230814212223335.png)

开启代理，使用burpsuite抓包。再次刷新页面，burpsuite中了以下请求

![image-20230814205916256](.\images\image-20230814205916256.png)

将请求放行之后，burpsuite还会拦截下另一个请求

![image-20230814210006620](.\images\image-20230814210006620.png)

将第二个请求也放行之后，就会正常的显示顾客信息。如果替换第二个请求中的参数内容，则会发现存在基于时间的盲注。payload为(select*from(select+sleep(3)union/**/select+1)a)，payload的url编码为%28select%2Afrom%28select%2Bsleep%283%29union%2F%2A%2A%2Fselect%2B1%29a%29，重新刷新页面，在第二个请求中替换member_id，页面返回时间延迟了3秒，并且顾客信息显示No matching records found。

![image-20230814212020677](.\images\image-20230814212020677.png)

![image-20230814212041218](.\images\image-20230814212041218.png)

### 3.自动验证

将抓到的http请求保存到本地，文件名为payload，在columns%5B0%5D%5Bdata%5D=的位置去掉原始参数，改为*。执行命令python sqlmap.py -r "payload"  --dbs --level 3，可以看到sqlmap验证了该位置为注入点，并且可以对数据库进行爆破

![image-20230814212702414](.\images\image-20230814212702414.png)

已经得到了information_schema和ample两个数据库名

![image-20230814212901612](.\images\image-20230814212901612.png)