import { writeFile } from "node:fs/promises";

process.on("SIGTERM", () => {});
setTimeout(() => writeFile(process.argv[2], "mutation after timeout\n", "utf8"), 300);
setInterval(() => {}, 1_000);
