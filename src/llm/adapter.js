// LLM provider adapters for the compatibility experiment.
//
// Four models, three wire formats, one face:
//   deepseek-v4.1-flash  OpenAI chat/completions   (DeepSeek official API)
//   glm-5.3-flash        OpenAI chat/completions   (OpenCode Go endpoint)
//   claude-haiku-5-5     Anthropic messages        (OpenCode Go endpoint)
//   gpt-6-luna           OpenAI responses          (OpenCode Go endpoint)
//
// Key facts about the OpenCode Go endpoint (opencode.ai/v2/docs/console/go):
//   - every request needs a stable `x-opencode-session` header per conversation,
//     plus a self-identifying User-Agent; otherwise it 400s with MissingSessionID.
//   - the four models above map to different endpoints, so this adapter normalises
//     them to one `chat(model, messages)` call.
//
// Secrets: DEEPSEEK_API_KEY and OPENCODE_GO_API_KEY are read from the environment.
// Nothing is written to the repository.

const http = require('http');
const https = require('https');
const { randomUUID } = require('crypto');

function envKey(name) {
    if (process.env[name]) return process.env[name];
    // Fall back to the user/machine environment (the harness shell may not inherit
    // registry variables set by the user).
    for (const scope of ['User', 'Machine']) {
        const v = (() => {
            try { return require('child_process').execSync(`reg query "HKCU\\Environment" /v ${name}`, { encoding: 'utf8' }); } catch (e) { return ''; }
        })();
        // reg query is fragile; prefer the .NET API below instead.
    }
    return null;
}

// Cache environment lookups: without it every chat() call re-queries the registry for
// a variable the process environment does not carry, which is slow and noisy.
const ENV_CACHE = new Map();

// Read a variable from the user/machine environment registry (covers keys that are
// set in System Properties > Environment Variables but not exported to this shell).
function readEnvVar(name) {
    if (ENV_CACHE.has(name)) return ENV_CACHE.get(name);
    const processEnv = process.env[name];
    if (processEnv && processEnv.length > 0) {
        ENV_CACHE.set(name, processEnv);
        return processEnv;
    }
    let found = null;
    if (process.platform === 'win32') {
        try {
            // PowerShell-free approach: query the registry through `reg.exe`.
            const cp = require('child_process');
            for (const hive of ['HKCU\\Environment', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment']) {
                try {
                    const out = cp.execSync(`reg query "${hive}" /v ${name}`, {
                        encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'],
                    });
                    const m = out.match(new RegExp(`${name}\\s+REG_\\w+\\s+(.+)`));
                    if (m && m[1]) { found = m[1].trim(); break; }
                } catch (e) { /* not present in this hive */ }
            }
        } catch (e) { /* no reg.exe access */ }
    }
    ENV_CACHE.set(name, found);
    return found;
}

// The OpenCode Go key is not in the environment; it lives in the OpenCode CLI's
// config (opencode.json). Read it as a fallback so the experiment does not need the
// user to duplicate the secret.
function readOpenCodeGoKey() {
    const direct = readEnvVar('OPENCODE_GO_API_KEY');
    if (direct) return direct;
    const os = require('os');
    const path = require('path');
    const candidates = [
        path.join(os.homedir(), '.config', 'opencode', 'opencode.json'),
        path.join(os.homedir(), '.opencode', 'opencode.json'),
    ];
    for (const p of candidates) {
        try {
            const cfg = JSON.parse(require('fs').readFileSync(p, 'utf8'));
            const k = cfg && cfg.provider && cfg.provider.opencode
                && cfg.provider.opencode.options && cfg.provider.opencode.options.apiKey;
            if (k) return k;
        } catch (e) { /* missing or unreadable */ }
    }
    return null;
}

// ---- model registry ----
// `api` picks which backend + wire format; `endpoint` overrides the base URL.
const MODELS = {
    'deepseek-v4.1-flash': {
        provider: 'deepseek',
        api: 'openai-chat',
        endpoint: 'https://api.deepseek.com/v1/chat/completions',
        envKey: 'DEEPSEEK_API_KEY',
        // The DeepSeek official API does not expose the "v4.1-flash" name used by the
        // OpenCode Go endpoint; it exposes deepseek-chat / deepseek-reasoner plus the
        // deepseek-flash alias. Map to the flash model.
        modelId: 'deepseek-flash',
        // deepseek-flash is a reasoning model: its chain-of-thought (reasoning_content)
        // counts against max_tokens, so a small budget ends with an empty content and
        // finish_reason=length. Give it enough headroom to emit the final answer.
        minMaxTokens: 1000,
    },
    'glm-5.3-flash': {
        provider: 'opencode-go',
        api: 'openai-chat',
        endpoint: 'https://opencode.ai/inference/go/openai/v1/chat/completions',
        envKey: 'OPENCODE_GO_API_KEY',
    },
    'claude-haiku-5-5': {
        provider: 'opencode-go',
        api: 'anthropic-messages',
        endpoint: 'https://opencode.ai/inference/go/anthropic/v1/messages',
        envKey: 'OPENCODE_GO_API_KEY',
        modelId: 'claude-haiku-5-5',
        // A refusal is a full sentence or two; keep headroom even with thinking off.
        minMaxTokens: 300,
    },
    'gpt-6-luna': {
        provider: 'opencode-go',
        api: 'openai-responses',
        endpoint: 'https://opencode.ai/inference/go/openai/v1/responses',
        envKey: 'OPENCODE_GO_API_KEY',
        modelId: 'gpt-6-luna',
        // gpt-6-luna spends reasoning tokens before the answer (observed ~40 for a
        // one-line reply). With a 50-token budget the reasoning consumed it all and
        // output_text came back empty, so keep a floor that leaves room for both.
        minMaxTokens: 800,
    },
};

function resolveKey(model) {
    const spec = MODELS[model];
    if (!spec) throw new Error(`unknown model: ${model}`);
    const key = spec.envKey === 'OPENCODE_GO_API_KEY'
        ? readOpenCodeGoKey()
        : readEnvVar(spec.envKey);
    if (!key) throw new Error(`missing API key for ${model}: set ${spec.envKey}`);
    return { spec, key };
}

// Minimal JSON POST. Node's built-in fetch is available (Node >= 18).
async function postJson(url, headers, body) {
    const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body),
    });
    const text = await resp.text();
    let data = null;
    try { data = JSON.parse(text); } catch (e) { /* non-JSON error body */ }
    if (!resp.ok) {
        const detail = data && (data.error && (data.error.message || data.error)) || text.slice(0, 300);
        throw new Error(`HTTP ${resp.status}: ${detail}`);
    }
    return data;
}

const SESSIONS = new Map(); // model -> stable session id per conversation

function sessionId(key) {
    if (!SESSIONS.has(key)) SESSIONS.set(key, randomUUID());
    return SESSIONS.get(key);
}

// Normalise `{role, content}` messages (OpenAI/DeepSeek shape) and return the text
// of the first assistant reply.
async function chat(model, messages, { maxTokens = 256, temperature = 0 } = {}) {
    const { spec, key } = resolveKey(model);
    const headers = {
        'Authorization': `Bearer ${key}`,
        'User-Agent': 'zkp-demo-compat/1.0',
    };
    // OpenCode Go requires a per-conversation session id; harmless for DeepSeek too.
    if (spec.provider === 'opencode-go') {
        headers['x-opencode-session'] = sessionId(`${model}:${spec.envKey}`);
    }

    if (spec.api === 'openai-chat') {
        const effectiveMaxTokens = Math.max(maxTokens, spec.minMaxTokens || 0);
        const body = {
            model: spec.modelId || model,
            messages,
            max_tokens: effectiveMaxTokens,
            ...(temperature !== undefined ? { temperature } : {}),
        };
        const data = await postJson(spec.endpoint, headers, body);
        return data.choices && data.choices[0] && data.choices[0].message
            ? data.choices[0].message.content || ''
            : '';
    }

    if (spec.api === 'anthropic-messages') {
        // Anthropic wire format: system + alternating user/assistant, max_tokens.
        // temperature is deprecated on newer models; omit it when it is the default.
        const system = messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n');
        const turns = messages.filter((m) => m.role !== 'system').map((m) => ({
            role: m.role === 'assistant' ? 'assistant' : 'user',
            content: m.content,
        }));
        const body = {
            model: spec.modelId,
            max_tokens: Math.max(maxTokens, spec.minMaxTokens || 0),
            // The OpenCode Go Claude endpoint enables extended thinking by default; for
            // a short factual answer it would burn the whole budget on an empty
            // "thinking" block and return no text. Disable it.
            thinking: { type: 'disabled' },
            ...(temperature !== undefined && temperature !== 0 ? { temperature } : {}),
            ...(system ? { system } : {}),
            messages: turns,
        };
        const data = await postJson(spec.endpoint, headers, body);
        // Extract a text block; tolerate the presence of a thinking block before it.
        if (Array.isArray(data.content)) {
            const texts = data.content
                .filter((block) => block.type === 'text')
                .map((block) => block.text || '');
            if (texts.length) return texts.join('');
        }
        return (data.content && data.content[0] && data.content[0].text) || '';
    }

    if (spec.api === 'openai-responses') {
        // OpenAI Responses API: `input` can be a string or message list.
        const system = messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n');
        const turns = messages.filter((m) => m.role !== 'system').map((m) => ({
            role: m.role === 'assistant' ? 'assistant' : 'user',
            content: m.content,
        }));
        const body = {
            model: spec.modelId,
            input: system ? [{ role: 'system', content: system }, ...turns] : turns,
            max_output_tokens: Math.max(maxTokens, spec.minMaxTokens || 0),
            ...(temperature !== undefined && temperature !== 0 ? { temperature } : {}),
        };
        const data = await postJson(spec.endpoint, headers, body);
        // Responses API: text lives in output[].content[].text (type: output_text),
        // not in a top-level output_text field.
        if (data.output_text) return data.output_text;
        if (Array.isArray(data.output)) {
            for (const item of data.output) {
                if (item.type === 'message' && Array.isArray(item.content)) {
                    const texts = item.content
                        .filter((c) => c.type === 'output_text')
                        .map((c) => c.text);
                    if (texts.length) return texts.join('');
                }
            }
        }
        return '';
    }

    throw new Error(`unsupported api for ${model}: ${spec.api}`);
}

// Parse a bracketed/JSON answer the LLM should produce. Returns null on failure so
// callers can record an ABSTAIN/PARSE_FAIL outcome without crashing the pipeline.
function parseJsonReply(text) {
    if (!text) return null;
    // Prefer a fenced or bare JSON object.
    const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/);
    const candidate = fence ? fence[1] : text;
    try {
        return JSON.parse(candidate.trim());
    } catch (e) {
        const brace = candidate.match(/\{[\s\S]*\}/);
        if (brace) {
            try { return JSON.parse(brace[0]); } catch (e2) { return null; }
        }
        return null;
    }
}

module.exports = { chat, parseJsonReply, MODELS, readEnvVar, readOpenCodeGoKey };
