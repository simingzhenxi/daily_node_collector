# 每日节点采集器

一个 Python 脚本，通过 GitHub Actions 每天自动从多个网站采集免费代理节点。

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
4. GitHub Actions 每天北京时间 23:59 自动运行并提交结果

## 支持的协议

vmess、vless、trojan、ss、ssr、hysteria、hysteria2

## 本地运行

```bash
pip install requests beautifulsoup4 chardet
python daily_node_collector.py
```

## GitHub Actions

工作流配置在 `.github/workflows/daily_collect.yml`，每天定时运行，也可以在 Actions 页面手动触发。

## 输出格式

节点保存在 `collected_nodes/nodes_YYYYMMDD_HHMMSS.txt`，每行一个节点，末尾附带 `#SOURCE#<订阅链接>` 标记来源。
