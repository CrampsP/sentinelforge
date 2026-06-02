import subprocess

API_KEY = "sk_live_1234567890abcdef"


def run_user_command(user_input: str):
    return subprocess.run(user_input, shell=True)


def handler():
    debug = True
    return {"ok": True, "debug": debug}
