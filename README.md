## 节点来源

- [cfmem.com](https://www.cfmem.com)
- [v2rayshare.net](https://v2rayshare.net)
- [nodefree.me](https://nodefree.me)
- [proxyqueen.top](https://www.proxyqueen.top)
- [clashfreenode.com](https://clashfreenode.com)

## 工作原理

1. 脚本自动爬取各来源网站，获取最新的订阅链接
2. 解码订阅内容（通常为 Base64 编码），提取节点信息
3. 节点去重后保存到 `collected_nodes/` 目录，附带来源信息

## 支持的协议

vmess、vless、trojan、ss、ssr、hysteria、hysteria2

## 本地运行

```bash
pip install requests beautifulsoup4 chardet
python daily_node_collector.py
```

