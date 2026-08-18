import logging
import shlex

logger = logging.getLogger("safe_pseudo_shell")


class SafePseudoShell:
    def __init__(self, filesystem: dict[str, str]):
        self.filesystem = filesystem
        self.execution_log: list[dict] = []

    def execute(self, command_string: str) -> str:
        logger.info("Command received: %s", command_string)
        try:
            parts = shlex.split(command_string)
        except ValueError:
            parts = command_string.split()

        if not parts:
            return ""

        cmd = parts[0]
        args = parts[1:]

        entry = {"command": cmd, "args": args, "raw": command_string}

        handler = getattr(self, f"_cmd_{cmd}", None)
        if handler:
            result = handler(args)
            entry["result"] = result
            entry["matched"] = True
        else:
            result = f"{cmd}: command not found"
            entry["result"] = result
            entry["matched"] = False

        self.execution_log.append(entry)
        logger.info("Result: %s", result[:200])
        return result

    def _cmd_cat(self, args: list[str]) -> str:
        if not args:
            return ""
        outputs = []
        for path in args:
            if path in self.filesystem:
                outputs.append(self.filesystem[path])
            else:
                outputs.append(f"cat: {path}: No such file or directory")
        return "\n".join(outputs)

    def _cmd_ls(self, args: list[str]) -> str:
        target = args[0] if args else "/"
        entries = []
        for path in self.filesystem:
            if path.startswith(target.rstrip("/") + "/") or (target == "/" and path.startswith("/")):
                relative = path[len(target.rstrip("/")) + 1:]
                top_level = relative.split("/")[0]
                if top_level and top_level not in entries:
                    entries.append(top_level)
        return "\n".join(sorted(entries)) if entries else ""

    def _cmd_id(self, args: list[str]) -> str:
        return "uid=0(root) gid=0(root) groups=0(root)"

    def _cmd_whoami(self, args: list[str]) -> str:
        return "root"

    def _cmd_uname(self, args: list[str]) -> str:
        return "Linux nas-320l 3.10.0 #1 SMP armv7l GNU/Linux"

    def _cmd_echo(self, args: list[str]) -> str:
        return " ".join(args)

    def _cmd_pwd(self, args: list[str]) -> str:
        return "/root"
