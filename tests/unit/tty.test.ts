import { describe, it, expect, vi, afterEach } from "vitest";
import { requireTTY } from "../../src/tty.js";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("requireTTY", () => {
  it("calls process.exit(1) when isTTY is falsy", () => {
    const original = process.stdin.isTTY;
    Object.defineProperty(process.stdin, "isTTY", { value: undefined, configurable: true });

    const exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("exit");
    });
    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    expect(() => requireTTY("test-command")).toThrow("exit");
    expect(exitSpy).toHaveBeenCalledWith(1);

    Object.defineProperty(process.stdin, "isTTY", { value: original, configurable: true });
    stderrSpy.mockRestore();
  });

  it("does not exit when isTTY is true", () => {
    const original = process.stdin.isTTY;
    Object.defineProperty(process.stdin, "isTTY", { value: true, configurable: true });

    const exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("exit");
    });

    expect(() => requireTTY("test-command")).not.toThrow();
    expect(exitSpy).not.toHaveBeenCalled();

    Object.defineProperty(process.stdin, "isTTY", { value: original, configurable: true });
  });

  it("error message includes the command name", () => {
    const original = process.stdin.isTTY;
    Object.defineProperty(process.stdin, "isTTY", { value: undefined, configurable: true });

    const exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("exit");
    });
    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    try {
      requireTTY("my-special-command");
    } catch {}

    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining("my-special-command"));

    Object.defineProperty(process.stdin, "isTTY", { value: original, configurable: true });
    stderrSpy.mockRestore();
    exitSpy.mockRestore();
  });

  it("error message mentions TTY", () => {
    const original = process.stdin.isTTY;
    Object.defineProperty(process.stdin, "isTTY", { value: undefined, configurable: true });

    const exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("exit");
    });
    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    try {
      requireTTY("cmd");
    } catch {}

    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining("TTY"));

    Object.defineProperty(process.stdin, "isTTY", { value: original, configurable: true });
    stderrSpy.mockRestore();
    exitSpy.mockRestore();
  });
});
