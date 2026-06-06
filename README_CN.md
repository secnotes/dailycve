# CVE 每日监控

[English](README.md) | [中文](README_CN.md)

自动化的每日CVE监控系统，每日从MITRE CVE收集所有漏洞信息，并生成易于阅读的报告，可以快速自定义筛选高风险漏洞。

## 🚀 功能特点

- **专注MITRE CVE**: 每日从MITRE CVE数据库及相关源获取所有CVE信息
- **智能过滤**: 基于以下条件识别高风险漏洞:
  - CVSS评分 > 7.0 (高危/严重级别)
  - 列入CISA KEV (已知利用漏洞) 清单
  - EPSS评分 ≥ 0.01 (利用概率)
- **AI精选**: 可选使用OpenAI兼容API智能分类和精选高危漏洞
  - 筛选CVSS ≥ 7.0且有描述信息的漏洞进行AI分析
  - 按领域分类：桌面操作系统、移动安全、IoT、云安全、网络设备、工控、Web安全、数据库与中间件
  - 为每条精选漏洞提供AI生成的推荐理由
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
│   ├── ai_provider.py            # AI接口（兼容OpenAI API）
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
   # 在.env文件中添加AI API密钥以启用AI精选功能
   # 支持 AI_API_KEY 或 OPENAI_API_KEY（向后兼容）
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
- 启用/禁用AI精选

## 🤖 AI精选

系统支持使用OpenAI兼容API对高危漏洞进行智能分类和精选。启用方法:

1. 在 `.env` 文件中添加API密钥:
   ```bash
   # 方式一：使用 AI_API_KEY（推荐，支持多家API提供商）
   AI_API_KEY=your_api_key_here
   AI_MODEL=gpt-4o-mini
   AI_BASE_URL=https://api.openai.com/v1

   # 方式二：使用 OPENAI_API_KEY（向后兼容）
   OPENAI_API_KEY=your_openai_key
   ```
2. 系统将自动执行以下操作:
   - 筛选CVSS ≥ 7.0且描述非空的漏洞
   - 将筛选后的漏洞发送至AI进行分析和分类
   - 生成「AI精选」视图，包含分类漏洞及推荐理由
3. 支持的API提供商：OpenAI、DeepSeek、阿里（DashScope）、月之暗面、智谱（GLM）等兼容OpenAI接口的服务

### AI分类类别

漏洞按以下领域进行分类:

| 类别 | 说明 |
|------|------|
| 💻 桌面操作系统 | Windows、macOS、Linux桌面漏洞 |
| 📱 移动安全 | Android、iOS、移动应用漏洞 |
| 📡 IoT安全 | 路由器、摄像头、嵌入式设备 |
| ☁️ 云安全 | AWS、Azure、GCP、云服务 |
| 🌐 网络设备 | Cisco、Fortinet、网络基础设施 |
| 🏭 工业控制 | SCADA、工业控制系统 |
| 🔐 Web安全 | 浏览器、Web框架、CMS |
| 🗄️ 数据库与中间件 | Oracle、MySQL、Apache、Nginx |
| 📌 其他 | 不属于以上类别的漏洞 |

### UI切换

启用AI精选后，HTML报告侧边栏顶部会显示切换按钮:
- **📋 全部漏洞**: 默认视图，显示所有采集的CVE
- **🤖 AI精选**: AI筛选后的分类视图，包含推荐理由

## 📈 输出文件

执行后，系统会生成:
- `docs/index.html`: 带有过滤功能和AI精选切换的交互式仪表板报告
- `docs/ai_curated.json`: AI精选结果缓存（启用AI时生成）
- `docs/reports/[year]/daily_cve_[date].md`: 每日发现的markdown存档

## 🏗️ 架构

### 1. 收集器 (`src/collector.py`)
- 每日从MITRE CVE数据库获取所有CVE信息
- 加载CISA KEV和EPSS数据集以补充MITRE CVE数据
- 基于风险标准过滤漏洞
- AI精选：使用AI对高危CVE进行分类，支持批量处理

### 2. AI接口 (`src/ai_provider.py`)
- 统一的OpenAI兼容API接口（支持OpenAI、DeepSeek、阿里等）
- 大量CVE列表的批量处理
- 自动推断模型到提供商URL的映射
- JSON响应解析与错误处理

### 3. 报告器 (`src/reporter.py`)
- 生成带有高级过滤UI的HTML报告
- 创建历史记录的markdown归档
- AI精选视图，包含分类导航和推荐理由
- 「全部漏洞」与「AI精选」视图切换
- 明暗主题支持

### 4. 配置 (`src/config.py`)
- 集中配置管理
- 风险阈值和API端点
- AI精选设置和分类定义
- 输出路径和设置