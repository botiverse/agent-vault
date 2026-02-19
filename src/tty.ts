import { createInterface } from "node:readline";

/**
 * Check if stdin is an interactive TTY.
 * Sensitive commands (set, get, rm, import) require this.
 */
export function requireTTY(commandName: string): void {
  if (!process.stdin.isTTY) {
    console.error(
      `✗ "${commandName}" requires an interactive terminal (TTY).\n` +
        `  This command handles secret values and cannot be run programmatically.\n` +
        `  Please run it directly in your terminal.`
    );
    process.exit(1);
  }
}

/**
 * Prompt for a value with masked input (shows dots instead of characters).
 */
export function promptSecret(prompt: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const rl = createInterface({
      input: process.stdin,
      output: process.stderr, // Use stderr so stdout stays clean
      terminal: true,
    });

    // Mask input
    process.stderr.write(prompt);

    const stdin = process.stdin;
    const originalRawMode = stdin.isRaw;
    if (stdin.setRawMode) stdin.setRawMode(true);

    let value = "";
    const onData = (ch: Buffer) => {
      const c = ch.toString("utf8");
      if (c === "\n" || c === "\r" || c === "\u0004") {
        // Enter or Ctrl+D
        if (stdin.setRawMode) stdin.setRawMode(originalRawMode ?? false);
        stdin.removeListener("data", onData);
        process.stderr.write("\n");
        rl.close();
        resolve(value);
      } else if (c === "\u0003") {
        // Ctrl+C
        if (stdin.setRawMode) stdin.setRawMode(originalRawMode ?? false);
        stdin.removeListener("data", onData);
        rl.close();
        reject(new Error("User cancelled"));
      } else if (c === "\u007F" || c === "\b") {
        // Backspace
        if (value.length > 0) {
          value = value.slice(0, -1);
          process.stderr.write("\b \b");
        }
      } else if (c.charCodeAt(0) >= 32) {
        // Printable character
        value += c;
        process.stderr.write("•");
      }
    };

    stdin.on("data", onData);
    stdin.resume();
  });
}

/**
 * Prompt for a yes/no confirmation.
 */
export function confirm(prompt: string, defaultYes: boolean = false): Promise<boolean> {
  return new Promise((resolve) => {
    const rl = createInterface({
      input: process.stdin,
      output: process.stderr,
      terminal: true,
    });

    const hint = defaultYes ? "[Y/n]" : "[y/N]";
    rl.question(`${prompt} ${hint} `, (answer) => {
      rl.close();
      const a = answer.trim().toLowerCase();
      if (a === "") resolve(defaultYes);
      else resolve(a === "y" || a === "yes");
    });
  });
}
