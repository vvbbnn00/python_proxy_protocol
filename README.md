# 简介
此处介绍一种通过魔改代码实现让Python Web服务器支持Proxy Protocol的方法。本代码修改了http模块中BaseHTTPRequestHandler对象，因此，使用该模块作为Web服务器的所有应用，都支持Proxy Protocol，也就是说，在使用frp等软件进行端口穿透时，HTTP请求会被自动添加X-Forwarded-For和X-Real-IP标头，这会让获取真实IP更加简单。

# 实现方法
找到http/server.py中BaseHTTPRequestHandler对象，将本项目中的Python代码替换即可。

# 协议标准
参考：https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

# 测试
经过测试，IPv4协议无异常，IPv6因条件限制无法测试，如有问题，欢迎发Issue或联系我！
