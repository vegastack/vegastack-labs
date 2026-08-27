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
    terminationGraceMs = 1_000,
    timeoutMs = 300_000,
  } = options;

  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      detached: process.platform !== "win32",
      env,
      shell: false,
      stdio: capture ? ["ignore", "pipe", "pipe"] : "inherit",
      windowsHide: true,
    });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let interruptedBy = null;
    let terminating = false;
    let settled = false;
    let escalationTimer;
    let finalTimer;

    const relaySignals =
      process.platform === "win32" ? ["SIGINT", "SIGTERM"] : ["SIGHUP", "SIGINT", "SIGTERM"];

    function signalTree(signal) {
      if (!child.pid) {
        return;
      }
      try {
        if (process.platform === "win32") {
          const killer = spawn("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], {
            shell: false,
            stdio: "ignore",
            windowsHide: true,
          });
          killer.on("error", () => child.kill(signal));
          killer.unref();
        } else {
          process.kill(-child.pid, signal);
        }
      } catch (error) {
        child.kill(signal);
      }
    }

    const signalHandlers = new Map();

    function cleanup() {
      clearTimeout(timer);
      clearTimeout(escalationTimer);
      clearTimeout(finalTimer);
      for (const [signal, handler] of signalHandlers) {
        process.removeListener(signal, handler);
      }
    }

    function finish(error, result) {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      if (error) {
        reject(error);
      } else {
        resolve(result);
      }
    }

    function terminationError(code = null, signal = null) {
      if (timedOut) {
        return new CommandError(`${command} exceeded ${timeoutMs} ms`, {
          command,
          args,
          code,
          signal,
          timedOut: true,
        });
      }
      return new CommandError(`${command} was interrupted by ${interruptedBy}`, {
        command,
        args,
        code,
        signal: signal ?? interruptedBy,
      });
    }

    function terminate(signal = "SIGTERM") {
      if (terminating) {
        return;
      }
      terminating = true;
      signalTree(signal);
      escalationTimer = setTimeout(() => {
        signalTree("SIGKILL");
        finalTimer = setTimeout(() => {
          child.stdout?.destroy();
          child.stderr?.destroy();
          child.unref();
          finish(terminationError(null, "SIGKILL"));
        }, Math.max(50, terminationGraceMs));
        finalTimer.unref();
      }, terminationGraceMs);
      escalationTimer.unref();
    }

    for (const signal of relaySignals) {
      const handler = () => {
        if (!timedOut && !interruptedBy) {
          interruptedBy = signal;
          terminate(signal);
        }
      };
      signalHandlers.set(signal, handler);
      process.once(signal, handler);
    }

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
      if (interruptedBy) {
        return;
      }
      timedOut = true;
      terminate();
    }, timeoutMs);
    timer.unref();

    child.on("error", (error) => {
      finish(
        new CommandError(`unable to start ${command}: ${error.message}`, {
          command,
          args,
        }),
      );
    });

    child.on("close", (code, signal) => {
      if (timedOut || interruptedBy) {
        finish(terminationError(code, signal));
        return;
      }

      if (code !== 0) {
        finish(
          new CommandError(`${command} exited with status ${code ?? "unknown"}`, {
            command,
            args,
            code,
            signal,
          }),
        );
        return;
      }

      finish(null, { code, signal, stdout, stderr });
    });
  });
}
