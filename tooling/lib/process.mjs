import { spawn } from "node:child_process";

export class CommandError extends Error {
  constructor(message, { command, args, code = null, signal = null, timedOut = false } = {}) {
    super(message);
    this.name = "CommandError";
    this.command = command;
    this.args = args;
    this.code = code;
    this.signal = signal;
    this.timedOut = timedOut;
  }
}

export function packageManagerInvocation(args) {
  if (process.env.npm_execpath) {
    return { command: process.execPath, args: [process.env.npm_execpath, ...args] };
  }

  return {
    command: process.platform === "win32" ? "pnpm.cmd" : "pnpm",
    args,
  };
}

export function runCommand(command, args = [], options = {}) {
  const {
    capture = false,
    cwd = process.cwd(),
    env = process.env,
    timeoutMs = 300_000,
  } = options;

  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env,
      shell: false,
      stdio: capture ? ["ignore", "pipe", "pipe"] : "inherit",
      windowsHide: true,
    });

    let stdout = "";
    let stderr = "";
    let timedOut = false;

    if (capture) {
      child.stdout.setEncoding("utf8");
      child.stderr.setEncoding("utf8");
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
      });
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
    }

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);
    timer.unref();

    child.on("error", (error) => {
      clearTimeout(timer);
      reject(
        new CommandError(`unable to start ${command}: ${error.message}`, {
          command,
          args,
        }),
      );
    });

    child.on("close", (code, signal) => {
      clearTimeout(timer);

      if (timedOut) {
        reject(
          new CommandError(`${command} exceeded ${timeoutMs} ms`, {
            command,
            args,
            code,
            signal,
            timedOut: true,
          }),
        );
        return;
      }

      if (code !== 0) {
        reject(
          new CommandError(`${command} exited with status ${code ?? "unknown"}`, {
            command,
            args,
            code,
            signal,
          }),
        );
        return;
      }

      resolve({ code, signal, stdout, stderr });
    });
  });
}
