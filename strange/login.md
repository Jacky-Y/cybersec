为了保留之前的网页和打开的程序，让电脑一直进入睡眠模式，保持了一天一夜，回来进入系统的时候，发现无法登录了，提示为 **你的设备处于脱机状态，请尝试其他登录方式**，但是并没有提示任何其他登录方式，只能用PIN登录，于是连接上wifi，再登录，还是这样报错，反复尝试登录都是这样报错。再点击重置PIN，需要登录微软账号，然后发送验证邮件，输入验证码之后，重置失败，总之就是，无法使用原来的PIN登录， 也无法修改PIN，因为根据提示还处于脱机状态。



思路1

然后在网上找资料，没有我这个报错的解决方法，只有一个类似报错的，系统提示要重置PIN，但又重置不了，按照网上的思路，可以按住shift，再点击重启键，就可以进入疑难解答页面， 在疑难解答页面可以开启cmd，但是需要输入密码，这个密码是之前很早的微软账户密码，微软账户的最新密码反而无法使用，应该是系统这个模块没有更新密码。进入cmd之后，**主要操作是move c:\windows\system32\cmd.exe c:\windows\system32\utilman.exe，本质是用cmd的程序去覆盖“轻松使用”程序，这个轻松使用就是在登录页面关机键的旁边的一个按钮，覆盖完成之后，再进入正常登录页面，点击“轻松使用”，就会弹出cmd**，这时候相当于在登录页面获取了访问cmd的权限，网上说剩下只需要在cmd中输入 msconfig ，然后设置为正常启动即可，但是这种方式对我来说没有用，还是会报错  **你的设备处于脱机状态，请尝试其他登录方式**。

思路2

在能访问cmd之后，至少多了一些操作的可能，在cmd页面可以运行notepad，然后在记事本里点打开，可以查看我的电脑存储的文件之类的，发现c盘只有1.5MB可用，又怀疑是c盘爆满导致无法写入所以登录失败，于是通过命令行的del xxx命令去我的下载文件下，把不用的文件都清一遍，再用rd /s /q C:\$Recycle.bin清理c盘下的回收站文件，这样c盘这时候已经有1.5G的空余了，但尝试登录还是失败

思路3

又在网上搜索，在可以访问命令行的情况下，如果不知道当前用户名和密码如何登入系统。如果命令行有管理员权限的话，可以通过以下命令创建一个密码为password，账户名为NewAdmin的用户

```
net user NewAdmin password /add
```

然后设置该用户为管理员权限，加入管理员组中

```
net localgroup Administrators NewAdmin /add
```

这两条命令执行成功之后，重启，发现多了NewAdmin用户，登录成功，可以进入NewAdmin账户的新系统，总算能进入系统了，但是即使新账户是管理员用户，还是无法修改原始账户的PIN码

思路4 

最后再去看报错提示，很奇怪为什么说是处于脱机状态，明明连上了wifi，而且重置密码的时候还可以发送验证邮件，说明可以访问微软服务器，但是最后一步重置失败，可能是微软某些服务访问失败？突然想到会不会是clash代理一直在后台运行导致流量无法正常达到微软服务器，于是进入NewAdmin账户系统，打开clash，clash 控制台果然显示rule模式，也就是clash一直在后台运行，把clash改为直连模式，返回登录页面，总算可以进入原始账户。

后记

后来查了下资料在可以访问控制台时，可以通过如下命令找到clash

```
tasklist | findstr "clash"
```

然后再结束进程

```
taskkill /f /t /im clash-win64.exe
```

