# CVE 每日监控

[English](README.md) | [中文](README_CN.md)

自动化的每日CVE监控系统，每日从MITRE CVE收集所有漏洞信息，并生成易于阅读的报告，可以快速自定义筛选高风险漏洞。

## 🚀 功能特点

- **专注MITRE CVE**: 每日从MITRE CVE数据库及相关源获取所有CVE信息
- **智能过滤**: 基于以下条件识别高风险漏洞:
  - CVSS评分 > 7.0 (高危/严重级别)
  - 列入CISA KEV (已知利用漏洞) 清单
  - EPSS评分 ≥ 0.01 (利用概率)
- **AI增强**: 可选择使用OpenAI改善漏洞描述的可读性
- **交互式报告**: 生成丰富的HTML报告，包含多种过滤功能:
  - CVSS严重等级过滤器 (严重、高危、中等、低危)
  - 状态过滤器 (最近修改、新发布)
  - 供应商过滤器，带有"显示更多"功能
  - 针对技术细节的增强型代码块渲染
- **历史归档**: 以Markdown格式按年度归档每日报告
- **自动更新**: 通过GitHub Actions定时执行

## 📁 项目结构

```
dailycve/
├── src/                           # 源代码
│   ├── __init__.py               # 包初始化
│   ├── collector.py              # 主CVE收集逻辑
│   ├── reporter.py               # 报告生成逻辑，包含增强UI
│   └── config.py                 # 配置设置
├── docs/                         # 生成的报告和文档
│   ├── index.html                # 交互式仪表板报告
│   └── reports/                  # 按年度归档的报告
│       └── [year]/               # 按年度的子目录
│           └── daily_cve_[date].md # 每日markdown报告
├── .github/
│   └── workflows/
│       └── daily-update.yml      # GitHub Actions工作流程
├── test_collector.py             # 验证测试脚本
├── requirements.txt              # Python依赖
├── .env.example                  # 环境配置示例
└── README_CN.md                  # 项目文档（中文版）
```

## ⚙️ 安装设置

1. **克隆仓库**:
   ```bash
   git clone https://github.com/secnotes/dailycve.git
   cd dailycve
   ```

2. **安装依赖**:
   ```bash
   pip install -r requirements.txt
   ```

3. **配置环境 (可选)**:
   ```bash
   cp .env.example .env
   # 在.env文件中添加您的OpenAI API密钥以启用AI增强描述
   ```

4. **本地运行**:
   ```bash
   python src/main.py
   ```

## 🛠️ 配置

系统使用位于 `src/config.py` 的几个配置参数:

- `CVSS_THRESHOLD`: 认为漏洞高风险的最低CVSS评分 (默认: 7.0)
- `EPSS_THRESHOLD`: 高风险分类的最低EPSS评分 (默认: 0.01)
- `LOOKBACK_DAYS`: 查找新CVE的回溯天数 (默认: 1)

## 📊 风险分类标准

满足以下任一条件的漏洞将被识别为高风险:
- CVSS评分 > 7.0 (高危或严重级别)
- 列入CISA KEV (已知利用漏洞清单)
- EPSS评分 ≥ 0.01 (更高的利用可能性)

## 🔧 自定义

您可以通过修改 `src/config.py` 来自定义系统行为:
- 调整风险阈值
- 更改报告输出路径
- 修改数据源URL
- 启用/禁用AI增强

## 🤖 AI增强

系统支持使用OpenAI增强漏洞描述的可读性。启用方法:
1. 在 `.env` 文件中添加您的 `OPENAI_API_KEY`
2. 系统将自动增强描述以提高可读性

## 📈 输出文件

执行后，系统会生成:
- `docs/index.html`: 带有过滤功能的交互式仪表板报告
- `docs/reports/[year]/daily_cve_[date].md`: 每日发现的markdown存档

## 🏗️ 架构

### 1. 收集器 (`src/collector.py`)
- 每日从MITRE CVE数据库获取所有CVE信息
- 加载CISA KEV和EPSS数据集以补充MITRE CVE数据
- 基于风险标准过滤漏洞
- 可选择使用AI增强描述

### 2. 报告器 (`src/reporter.py`)
- 生成带有高级过滤UI的HTML报告
- 创建历史记录的markdown归档
- 为易读性格式化漏洞数据
- 实现增强的代码块渲染和供应商过滤

### 3. 配置 (`src/config.py`)
- 集中配置管理
- 风险阈值和API端点
- 输出路径和设置