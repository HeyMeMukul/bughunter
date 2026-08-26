#!/usr/bin/env python3
"""
api_spider.py — OpenAPI/Swagger + GraphQL-driven Spider
For API-heavy programs, parses API specs and discovers every endpoint, parameter,
and schema automatically. Replaces HTML-based spidering for REST/GraphQL targets.
"""

import json
import sys
import argparse
import os
import re
import urllib.request
import urllib.error
import ssl
from typing import Dict, Any, List, Optional


class APISpider:
    """Discovers endpoints from OpenAPI/Swagger specs and GraphQL schemas."""

    def __init__(self, base_url: str, output_dir: str):
        self.base_url = base_url.rstrip("/")
        self.output_dir = output_dir
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE

    def fetch(self, url: str, timeout: int = 10) -> Optional[str]:
        """Fetch URL and return text content."""
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/json, application/yaml, */*",
                },
            )
            resp = urllib.request.urlopen(req, context=self.ssl_ctx, timeout=timeout)
            return resp.read().decode("utf-8", errors="ignore")
        except Exception as e:
            return None

    def find_api_specs(self) -> List[str]:
        """Auto-discover API specification endpoints."""
        candidates = [
            "/swagger.json",
            "/swagger/v1/swagger.json",
            "/api/swagger.json",
            "/api-docs",
            "/api-docs.json",
            "/v2/api-docs",
            "/v3/api-docs",
            "/openapi.json",
            "/openapi.yaml",
            "/api/openapi.json",
            "/docs/api",
            "/spec.json",
            "/api/spec",
            "/schema",
            "/swagger.yml",
            "/api/swagger.yml",
        ]

        found = []
        for path in candidates:
            url = f"{self.base_url}{path}"
            text = self.fetch(url)
            if text and ('"swagger"' in text.lower() or '"openapi"' in text.lower() or '"paths"' in text.lower()):
                found.append(url)
                print(f"  [+] OpenAPI spec found: {url}")

        # Check GraphQL
        graphql_candidates = [
            "/graphql",
            "/api/graphql",
            "/gql",
            "/query",
            "/v1/graphql",
            "/graphql/v1",
        ]
        for path in graphql_candidates:
            url = f"{self.base_url}{path}"
            text = self.fetch(f"{url}?query=%7B__schema%7Btypes%7Bname%7D%7D%7D")
            if text and '"data"' in text and '"__schema"' in text:
                found.append(f"{url}?query=INTROSPECTION")
                print(f"  [+] GraphQL endpoint (introspection enabled): {url}")

        return found

    def parse_openapi(self, spec_text: str) -> Dict[str, Any]:
        """Parse OpenAPI/Swagger spec to extract all endpoints."""
        try:
            spec = json.loads(spec_text)
        except json.JSONDecodeError:
            # Try YAML (basic conversion)
            spec = self._parse_yaml_simple(spec_text)

        endpoints = []
        paths = spec.get("paths", {})
        servers = spec.get("servers", [{"url": self.base_url}])
        base = servers[0].get("url", self.base_url) if servers else self.base_url

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
                    continue
                if not isinstance(details, dict):
                    continue

                params = []
                for p in details.get("parameters", []):
                    params.append({
                        "name": p.get("name", ""),
                        "in": p.get("in", ""),
                        "required": p.get("required", False),
                        "type": p.get("schema", {}).get("type", "string") if "schema" in p else p.get("type", "string"),
                    })

                # Extract request body schema
                body_params = []
                request_body = details.get("requestBody", {})
                if request_body:
                    content = request_body.get("content", {})
                    json_content = content.get("application/json", {})
                    schema = json_content.get("schema", {})
                    if schema.get("properties"):
                        for prop_name, prop_info in schema["properties"].items():
                            body_params.append({
                                "name": prop_name,
                                "type": prop_info.get("type", "string"),
                                "required": prop_name in schema.get("required", []),
                            })

                # Security
                security = details.get("security", spec.get("security", []))

                endpoints.append({
                    "id": f"API-{len(endpoints)+1:03d}",
                    "url": f"{base}{path}",
                    "method": method.upper(),
                    "summary": details.get("summary", details.get("description", ""))[:200],
                    "tags": details.get("tags", []),
                    "params": params,
                    "body_params": body_params,
                    "responses": list(details.get("responses", {}).keys()),
                    "security": [list(s.keys()) for s in security] if security else [],
                    "deprecated": details.get("deprecated", False),
                })

        return {
            "meta": {
                "title": spec.get("info", {}).get("title", "Unknown API"),
                "version": spec.get("info", {}).get("version", "unknown"),
                "openapi_version": spec.get("openapi", spec.get("swagger", "unknown")),
                "base_url": base,
            },
            "total_endpoints": len(endpoints),
            "endpoints": endpoints,
        }

    def parse_graphql_introspection(self, url: str) -> Dict[str, Any]:
        """Perform GraphQL introspection and extract schema."""
        introspection_query = """
        {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              name
              kind
              description
              fields {
                name
                description
                args { name type { name kind } }
                type { name kind }
              }
            }
          }
        }
        """

        text = self.fetch(url, timeout=15)
        if not text:
            return {"error": "No introspection response"}

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return {"error": "Invalid JSON response"}

        schema = data.get("data", {}).get("__schema", {})

        queries = []
        mutations = []
        query_type = schema.get("queryType", {}).get("name", "")
        mutation_type = schema.get("mutationType", {}).get("name", "")

        for gql_type in schema.get("types", []):
            kind = gql_type.get("kind", "")
            if kind == "OBJECT":
                name = gql_type.get("name", "")
                for field in gql_type.get("fields", []):
                    field_name = field.get("name", "")
                    args = field.get("args", [])
                    arg_names = [a.get("name", "") for a in args]
                    type_info = field.get("type", {}).get("name", "Unknown")

                    entry = {
                        "name": field_name,
                        "return_type": type_info,
                        "args": arg_names,
                        "description": field.get("description", "")[:200],
                    }

                    if name == query_type:
                        queries.append(entry)
                    elif name == mutation_type:
                        mutations.append(entry)

        # Generate test queries
        test_queries = []
        for q in queries[:10]:
            args_str = ", ".join(f"${a}: String" for a in q["args"][:3])
            fields_str = q["name"]
            test_queries.append(f"query {q['name']}({args_str}) {{ {fields_str} }}")

        for m in mutations[:5]:
            args_str = ", ".join(f"${a}: String!" for a in m["args"][:3])
            test_queries.append(f"mutation {m['name']}({args_str}) {{ {m['name']} }}")

        return {
            "meta": {
                "endpoint": url,
                "query_type": query_type,
                "mutation_type": mutation_type,
                "has_mutations": bool(mutations),
            },
            "queries": queries,
            "mutations": mutations,
            "test_queries": test_queries,
        }

    def _parse_yaml_simple(self, text: str) -> Dict[str, Any]:
        """Basic YAML to JSON conversion for OpenAPI specs."""
        result: Dict[str, Any] = {"paths": {}, "info": {}, "servers": []}

        current_path = None
        current_method = None

        for line in text.split("\n"):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Detect path
            path_match = re.match(r"^/(\S+):", stripped)
            if path_match:
                current_path = "/" + path_match.group(1)
                if current_path not in result["paths"]:
                    result["paths"][current_path] = {}
                continue

            # Detect method
            method_match = re.match(r"^(get|post|put|patch|delete|options):", stripped.lower())
            if method_match and current_path:
                current_method = method_match.group(1)
                result["paths"][current_path][current_method] = {
                    "summary": "",
                    "parameters": [],
                    "responses": {"200": {}},
                    "tags": [],
                    "deprecated": False,
                }
                continue

            # Extract summary
            summary_match = re.match(r"^summary:\s*(.+)", stripped)
            if summary_match and current_method:
                result["paths"][current_path][current_method]["summary"] = summary_match.group(1)

        return result

    def run(self) -> Dict[str, Any]:
        """Execute full API spidering."""

        os.makedirs(self.output_dir, exist_ok=True)

        print(f"[*] API Spider: {self.base_url}")
        print(f"[*] Output: {self.output_dir}")

        # Step 1: Find API specs
        specs = self.find_api_specs()

        # Step 2: Parse each spec
        api_result = {"openapi": [], "graphql": [], "total_endpoints": 0, "specs_found": specs}

        for spec_url in specs:
            if "graphql" in spec_url.lower() or "introspection" in spec_url.lower():
                gql_data = self.parse_graphql_introspection(spec_url.replace("?query=INTROSPECTION", ""))
                api_result["graphql"].append(gql_data)
                q_count = len(gql_data.get("queries", []))
                m_count = len(gql_data.get("mutations", []))
                print(f"  => {q_count} queries, {m_count} mutations")
                api_result["total_endpoints"] += q_count + m_count
            else:
                spec_text = self.fetch(spec_url)
                if spec_text:
                    parsed = self.parse_openapi(spec_text)
                    api_result["openapi"].append(parsed)
                    ep_count = parsed["total_endpoints"]
                    print(f"  => {ep_count} endpoints from {parsed['meta']['title']}")
                    api_result["total_endpoints"] += ep_count

        # Step 3: Write output
        output_path = os.path.join(self.output_dir, "api_spider.json")
        with open(output_path, "w") as f:
            json.dump(api_result, f, indent=2)

        # Also write endpoint list for Phase 2
        endpoints_list = []
        for spec in api_result["openapi"]:
            base = spec["meta"]["base_url"]
            for ep in spec["endpoints"]:
                endpoints_list.append(f"{ep['method']} {ep['url']}")

        with open(os.path.join(self.output_dir, "api_endpoints.txt"), "w") as f:
            f.write("\n".join(endpoints_list))

        print(f"\n[*] API Spider complete:")
        print(f"    Specs found:    {len(specs)}")
        print(f"    Total endpoints: {api_result['total_endpoints']}")
        print(f"    Output:          {output_path}")

        return api_result


def main():
    parser = argparse.ArgumentParser(description="OpenAPI/GraphQL API Spider")
    parser.add_argument("--base-url", required=True, help="Base URL of the target")
    parser.add_argument("--output-dir", default="engagement/spider/api", help="Output directory")
    args = parser.parse_args()

    spider = APISpider(args.base_url, args.output_dir)
    result = spider.run()

    print(json.dumps({"total": result["total_endpoints"]}))


if __name__ == "__main__":
    main()
