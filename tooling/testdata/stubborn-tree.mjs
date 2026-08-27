import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

process.on("SIGTERM", () => {});
spawn(process.execPath, [fileURLToPath(new URL("late-writer.mjs", import.meta.url)), process.argv[2]], {
  stdio: "ignore",
});
setInterval(() => {}, 1_000);
