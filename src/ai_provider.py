#!/usr/bin/env python3
"""
AI Provider Module - Unified interface for AI API calls
Supports OpenAI-compatible APIs (OpenAI, DeepSeek, Alibaba, etc.)
Adapted from secnews project for CVE analysis.
"""

import os
import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

# Load .env file if available
try:
    from dotenv import load_dotenv
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)

    env_paths = [
        os.path.join(script_dir, '.env'),
        os.path.join(project_root, '.env'),
        '.env',
    ]

    for env_path in env_paths:
        if os.path.exists(env_path):
            load_dotenv(env_path)
            break
except ImportError:
    pass

logger = logging.getLogger(__name__)

# Default base URLs for popular providers
DEFAULT_BASE_URLS = {
    'openai': 'https://api.openai.com/v1',
    'deepseek': 'https://api.deepseek.com/v1',
    'alibaba': 'https://dashscope.aliyuncs.com/compatible-mode/v1',
    'moonshot': 'https://api.moonshot.cn/v1',
    'zhipu': 'https://open.bigmodel.cn/api/paas/v4',
}

# Model to provider mapping for base_url hints
MODEL_PROVIDER_HINTS = {
    'claude': 'anthropic',
    'gpt': 'openai',
    'o1': 'openai',
    'o3': 'openai',
    'deepseek': 'deepseek',
    'qwen': 'alibaba',
    'kimi': 'moonshot',
    'glm': 'zhipu',
}


class AIProvider:
    """Unified AI provider using OpenAI-compatible interface"""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        """
        Initialize AI provider

        Args:
            api_key: API key (defaults to AI_API_KEY env var)
            model: Model name (defaults to AI_MODEL env var, or 'gpt-4o-mini')
            base_url: API base URL (defaults to AI_BASE_URL env var, or auto-inferred)
        """
        self.api_key = api_key or os.environ.get('AI_API_KEY')
        self.model = model or os.environ.get('AI_MODEL') or 'gpt-4o-mini'
        self.base_url = base_url or os.environ.get('AI_BASE_URL')

        if not self.api_key:
            raise ValueError("AI API key is required. Set AI_API_KEY env var.")

        # Auto-infer base_url if not provided
        if not self.base_url:
            self.base_url = self._infer_base_url(self.model)

        logger.info(f"AI Provider initialized: model={self.model}, base_url={self.base_url}")

    def _infer_base_url(self, model: str) -> str:
        """Infer base_url from model name"""
        for model_prefix, provider in MODEL_PROVIDER_HINTS.items():
            if model.lower().startswith(model_prefix):
                if provider in DEFAULT_BASE_URLS:
                    return DEFAULT_BASE_URLS[provider]
        return DEFAULT_BASE_URLS['openai']

    def analyze(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 8192,
        temperature: float = 0.3,
    ) -> str:
        """
        Send prompt to AI and get response

        Args:
            prompt: User prompt
            system_prompt: System prompt (optional)
            max_tokens: Max tokens in response
            temperature: Temperature for randomness

        Returns:
            AI response text
        """
        try:
            from openai import OpenAI
            import httpx
        except ImportError:
            raise ImportError("openai and httpx packages are required. Install with: pip install openai httpx")

        http_client = httpx.Client(
            timeout=httpx.Timeout(300.0, connect=30.0),
            follow_redirects=True,
        )

        client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            http_client=http_client,
        )

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        logger.info(f"Sending AI request with {len(prompt)} chars prompt...")

        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )

        result = response.choices[0].message.content
        logger.info(f"AI response received: {len(result)} chars")

        return result

    def analyze_cves(
        self,
        cves: List[Dict[str, Any]],
        categories: Optional[List[str]] = None,
        batch_size: int = 100,
    ) -> Dict[str, Any]:
        """
        Analyze CVE vulnerabilities and categorize important ones
        Uses batch processing to handle large CVE lists

        Args:
            cves: List of CVE dicts with id, description, cvss_score, epss_score,
                  in_cisa_kev, vendors, products, published_date
            categories: List of category names (defaults to predefined CVE categories)
            batch_size: Number of CVEs per batch (default 100)

        Returns:
            Dict with categorized CVEs and analysis metadata
        """
        if not categories:
            categories = [
                "桌面操作系统",
                "移动安全",
                "IoT安全",
                "云安全",
                "网络设备",
                "工业控制",
                "Web安全",
                "数据库与中间件",
                "其他",
            ]

        # Process in batches to avoid timeout
        all_results = []
        total_batches = (len(cves) // batch_size) + (1 if len(cves) % batch_size > 0 else 0)

        logger.info(f"Processing {len(cves)} CVEs in {total_batches} batches (batch_size={batch_size})")

        for batch_num in range(total_batches):
            start_idx = batch_num * batch_size
            end_idx = min(start_idx + batch_size, len(cves))
            batch_cves = cves[start_idx:end_idx]

            logger.info(f"Processing batch {batch_num + 1}/{total_batches}: {len(batch_cves)} CVEs")

            cves_text = self._format_cves_for_ai(batch_cves)

            system_prompt = """你是一位网络安全领域的专业漏洞分析师。你的任务是分析每日CVE漏洞数据，筛选出重要漏洞并进行分类。
你需要根据漏洞描述、CVSS评分、影响厂商和产品来判断漏洞的主题和重要性，将漏洞分配到合适的分类中。
请保持客观、专业，优先关注有实际攻击价值的漏洞。"""

            prompt = f"""请分析以下CVE漏洞数据，筛选出重要漏洞并按影响领域分类。

## 分类类别
{json.dumps(categories, ensure_ascii=False, separators=(',', ':'))}

## 分析要求
1. 筛选标准：CVSS评分>=7.0的高危漏洞，或已被CISA KEV收录的在野利用漏洞
2. 每个分类选择最相关的漏洞（如果该分类有足够漏洞）
3. 如果漏洞不适合任何分类或重要性较低，可以不收录
4. 为每条收录的漏洞提供简短的推荐理由（1-2句话，说明为什么该漏洞值得重点关注）

## 漏洞列表（共 {len(batch_cves)} 条，批次 {batch_num + 1}/{total_batches}）
{cves_text}

## 输出格式
请严格按照以下 JSON 格式返回，不要添加任何额外内容：
```json
{{"analysis_date":"YYYY-MM-DD","total_analyzed":{len(batch_cves)},"batch_number":{batch_num + 1},"categories":{{"桌面操作系统":[{{"id":"CVE-YYYY-NNNNN","reason":"推荐理由"}}]}},"summary":"本批次分析摘要（50字以内）"}}
```

请开始分析并返回 JSON 结果。"""

            try:
                response_text = self.analyze(prompt, system_prompt)
                batch_result = self._parse_json_response(response_text)
                all_results.append(batch_result)
                logger.info(f"Batch {batch_num + 1} completed successfully")
            except Exception as e:
                logger.error(f"Error processing batch {batch_num + 1}: {str(e)}")
                continue

        # Merge all batch results
        merged_result = self._merge_batch_results(all_results, cves, categories)

        return merged_result

    def _merge_batch_results(
        self,
        batch_results: List[Dict[str, Any]],
        original_cves: List[Dict[str, Any]],
        categories: List[str],
    ) -> Dict[str, Any]:
        """Merge results from multiple batches into a single result"""
        merged = {
            "analysis_date": datetime.now().strftime('%Y-%m-%d'),
            "total_analyzed": len(original_cves),
            "categories": {},
            "summary": "",
        }

        # Initialize all categories
        for cat in categories:
            merged["categories"][cat] = []

        # Merge CVEs from all batches, deduplicating by CVE ID
        seen_ids = set()
        for batch in batch_results:
            batch_categories = batch.get("categories", {})
            for cat_name, cat_cves in batch_categories.items():
                if cat_name not in merged["categories"]:
                    merged["categories"][cat_name] = []
                for cve in cat_cves:
                    cve_id = cve.get("id", "")
                    if cve_id and cve_id not in seen_ids:
                        seen_ids.add(cve_id)
                        merged["categories"][cat_name].append(cve)

        # Collect summaries from all batches
        summaries = [b.get("summary", "") for b in batch_results if b.get("summary")]
        merged["summary"] = " | ".join(summaries[:3]) if summaries else "AI分析完成，已筛选重要漏洞并分类"

        total_curated = sum(len(cves) for cves in merged["categories"].values())
        logger.info(f"Merged {len(batch_results)} batches, total curated CVEs: {total_curated}")

        return merged

    def _format_cves_for_ai(self, cves: List[Dict[str, Any]]) -> str:
        """Format CVE list for AI prompt"""
        lines = []
        for i, cve in enumerate(cves, 1):
            cve_id = cve.get('id', 'Unknown')
            cvss = cve.get('cvss_score', 0)
            epss = cve.get('epss_score', 0)
            in_cisa = cve.get('in_cisa_kev', False)
            vendors = ', '.join(cve.get('vendors', [])) if cve.get('vendors') else 'N/A'
            desc = cve.get('description', 'No description')
            # Truncate description if too long
            if len(desc) > 300:
                desc = desc[:300] + '...'

            lines.append(f"{i}. [{cve_id}] CVSS: {cvss}")
            if epss > 0:
                lines.append(f"   EPSS: {epss:.4f}")
            if in_cisa:
                lines.append(f"   CISA KEV: 是（已知被利用）")
            lines.append(f"   厂商: {vendors}")
            lines.append(f"   描述: {desc}")
            lines.append("")

        return "\n".join(lines)

    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON from AI response, handling markdown code blocks"""
        text = response.strip()
        if text.startswith('```json'):
            text = text[7:]
        if text.startswith('```'):
            text = text[3:]
        if text.endswith('```'):
            text = text[:-3]
        text = text.strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {e}")
            # Save raw response for debugging
            script_dir = os.path.dirname(os.path.abspath(__file__))
            debug_file = os.path.join(script_dir, 'ai_response_debug.txt')
            with open(debug_file, 'w', encoding='utf-8') as f:
                f.write(f"JSON Parse Error: {e}\n\n")
                f.write(f"Raw Response (length={len(text)}):\n")
                f.write(text)
            logger.info(f"Raw response saved to {debug_file} for debugging")
            return {
                "analysis_date": "",
                "total_analyzed": 0,
                "categories": {},
                "summary": "",
                "error": str(e),
            }


def get_ai_provider(
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
) -> AIProvider:
    """
    Factory function to create AI provider

    Args:
        api_key: API key (optional, uses env var if not provided)
        model: Model name (optional, uses env var if not provided)
        base_url: Base URL (optional, auto-inferred if not provided)

    Returns:
        AIProvider instance
    """
    return AIProvider(api_key=api_key, model=model, base_url=base_url)
