# LLM, RAG and Agent Security Policy

- Treat user prompts, retrieved documents, web content, tool output and model-generated text as untrusted data, not as instructions with higher authority.
- Do not rely on system prompts as the only security boundary. Enforce authorization in application code and tool adapters.
- Enforce per-user and per-tenant retrieval authorization before content enters the model context; filter results server-side and test cross-tenant isolation.
- Validate tool/function arguments with strict schemas, authorize each action, use least-privilege credentials, and require human approval for high-impact/destructive actions.
- Never pass model output directly to a shell, SQL interpreter, dynamic evaluator, filesystem path, HTML sink or privileged API without context-specific validation.
- Limit prompt/context size, output length, rate, concurrency, cost and tool iterations. Apply timeouts and audit security-relevant decisions.
- Test direct and indirect prompt injection, sensitive-data disclosure, unsafe output handling, tool abuse, RAG access-control bypass and resource exhaustion in a dedicated authorized environment.
- Do not treat a model's refusal, a single passing prompt test, or a hidden system prompt as a reliable access-control mechanism.
- For Model Context Protocol (MCP) servers, treat each registered tool as a privileged API: validate its input schema, apply server-side authorization on every call, scope filesystem/network access, constrain command execution, and review the HTTP transport's authentication and origin/host controls. Static co-occurrence checks are indicators only; also test authorization boundaries in an isolated deployment.
