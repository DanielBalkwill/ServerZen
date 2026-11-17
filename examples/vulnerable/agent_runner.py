"""More planted issues for ServerZEN's AI-agent-specific checks.

Shows an agent "runner" that executes tool calls and builds prompts insecurely.
Do NOT copy these patterns. All credentials here are fake.

Try:  serverzen scan examples/vulnerable
"""
import subprocess

# hardcoded-secret: a credential committed in source (fake value).
OPENAI_API_KEY = "sk-ABCdef0123456789ABCdef0123456789"


def run_tool(cmd: str):
    # dangerous-exec: shell=True on a command string the agent may have built.
    return subprocess.run(cmd, shell=True)


def eval_expression(expr: str):
    # dangerous-exec: eval over a dynamic string = code injection.
    return eval(expr)


def build_system_prompt(memory: str, user_message: str) -> str:
    # prompt-injection-surface: stored memory + user text interpolated straight
    # into the system prompt, with no untrusted-data framing.
    system_prompt = f"You are a helpful agent.\nMemory: {memory}\nUser: {user_message}"
    return system_prompt
