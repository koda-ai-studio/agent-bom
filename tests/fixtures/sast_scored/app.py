import os
import pickle
import sqlite3
import subprocess

from flask import Flask, request
from mcp.server.fastmcp import FastMCP

app = Flask(__name__)
mcp = FastMCP("demo")


@app.route("/user")
def get_user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    return str(conn.execute(f"SELECT * FROM users WHERE id = {uid}").fetchall())


@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    return str(eval(expr))


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))


@mcp.tool()
def run_query(query: str) -> str:
    """Run a SQL query."""
    conn = sqlite3.connect("app.db")
    return str(conn.execute("SELECT * FROM t WHERE name = '" + query + "'").fetchall())


@mcp.tool()
def shell(cmd: str) -> str:
    """Run a shell command."""
    return os.popen(cmd).read()


@mcp.tool()
def summarize(doc: str) -> str:
    """Summarize a document."""
    import anthropic

    client = anthropic.Anthropic()
    prompt = "You are a helpful assistant. Summarize: " + doc
    return client.messages.create(model="claude-sonnet-4-5", max_tokens=100, messages=[{"role": "user", "content": prompt}]).content[0].text
