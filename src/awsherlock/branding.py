"""Dependency-free terminal identity used by human-facing commands."""

import sys
import re
import shutil
import unicodedata

BANNER = """⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⡖⠒⠲⠶⢤⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣀⣀⣀⣀⢀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⢷⡀⠀⠀⠀⠀⠉⠙⢷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⣤⣄⠀
⠀⣰⡿⠟⠛⠋⠉⠉⠉⠉⠉⠉⠙⠛⠛⠛⠻⠶⣶⣦⣤⣿⣦⡀⠀⠀⠀⠀⠈⠻⣦⣀⢀⣀⣀⣤⣴⠶⠾⠿⠟⠛⠛⠉⠉⠁⠙⡇
⣸⣏⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⠾⠛⠋⠁⢀⡀⠀⠀⠀⠀⠀⠀⠉⠛⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇
⠘⢿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⠛⠛⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡟⠀
⠀⠘⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡿⠁⠀
⠀⠀⠈⠻⣦⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡶⠾⠷⣶⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⡟⠛⠻⢶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠟⠀⠀⠀
⠀⠀⠀⠀⠘⠷⣤⡀⠀⠀⠀⠀⣰⡿⠋⢀⣴⡟⠛⣧⠀⠀⠀⠀⠀⠀⠀⠈⣱⡟⠻⣦⠀⠙⢷⣄⠀⠀⠀⠀⠀⠀⠀⢀⣾⠋⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠿⣶⣄⠀⣼⡟⠂⠀⢸⡟⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠸⡇⠀⠀⢻⣆⠀⠀⠀⢀⣀⣶⣟⠁⠀⠀⠀⠀⠀     █████╗ ██╗    ██╗███████╗██╗  ██╗███████╗██████╗ ██╗      ██████╗  ██████╗██╗  ██╗
⠀⠀⠀⢺⣟⠒⠶⠶⣤⡄⠀⣿⠀⠀⠀⢺⡇⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠈⢿⡄⠀⢠⣷⠀⠀⠀⢻⡜⠛⠛⠉⠉⠉⣽⠇⠀⠀⠀⠀⠀    ██╔══██╗██║    ██║██╔════╝██║  ██║██╔════╝██╔══██╗██║     ██╔═══██╗██╔════╝██║ ██╔╝
⠀⠀⠀⠀⠙⠷⣤⡀⠀⠀⠀⣿⡀⠀⠀⠀⢻⣄⣠⡟⠀⠀⠀⠀⠀⠀⠀⠀⠘⠷⣤⡾⠁⠀⠀⠀⢸⡇⠀⠀⠀⣠⡾⠃⠀⠀⠀⠀⠀⠀    ███████║██║ █╗ ██║███████╗███████║█████╗  ██████╔╝██║     ██║   ██║██║     █████╔╝
⠀⠀⠀⠀⠀⠀⠉⢻⡇⠀⢀⣈⡀⠀⠀⠀⠀⠉⠉⠀⠀⠚⠚⠛⠂⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠀⣀⡀⠀⢰⣞⠉⠀⠀⠀⠀⠀⠀⠀⠀    ██╔══██║██║███╗██║╚════██║██╔══██║██╔══╝  ██╔══██╗██║     ██║   ██║██║     ██╔═██╗
⠀⠀⠀⠀⠀⠀⠀⣾⠁⠛⠋⠿⠷⠀⠀⠀⠀⠀⠀⠀⢀⠀⣀⣀⣀⡀⣠⡀⠀⠀⠀⠀⠘⠻⠿⠿⠉⠀⠀⠀⠙⢿⡄⠀⠀⠀⠀⠀⠀⠀    ██║  ██║╚███╔███╔╝███████║██║  ██║███████╗██║  ██║███████╗╚██████╔╝╚██████╗██║  ██╗
⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠛⢿⣌⠉⠉⢹⡇⠀⠀⠀⠀⠀⠀⠀⢀⣄⣀⣀⣀⣀⣀⣿⡄⠀⠀⠀⠀⠀⠀    ╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝
⠀⠀⠀⠀⠀⠀⠘⠛⠛⠛⠋⠙⠻⣦⣤⣀⣀⠀⠀⠀⠀⠀⠀⠙⢷⣤⣼⠃⠀⠀⢀⣀⣠⣤⡶⠟⠋⠉⠋⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣟⠛⠛⠛⠛⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢿⣏⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⣶⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⢶⡶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

_LETTERS = {
    "A": (" ### ", "#   #", "#####", "#   #", "#   #"),
    "W": ("#   #", "#   #", "# # #", "## ##", "#   #"),
    "S": (" ####", "#    ", " ### ", "    #", "#### "),
    "H": ("#   #", "#   #", "#####", "#   #", "#   #"),
    "E": ("#####", "#    ", "#### ", "#    ", "#####"),
    "R": ("#### ", "#   #", "#### ", "#  # ", "#   #"),
    "L": ("#    ", "#    ", "#    ", "#    ", "#####"),
    "O": (" ### ", "#   #", "#   #", "#   #", " ### "),
    "C": (" ####", "#    ", "#    ", "#    ", " ####"),
    "K": ("#   #", "#  # ", "###  ", "#  # ", "#   #"),
}
ASCII_WORDMARK = "\n".join(
    " ".join(_LETTERS[letter][row] for letter in "AWSHERLOCK").rstrip()
    for row in range(5)
)


def terminal_banner(*, width: int | None = None, encoding: str | None = None) -> str:
    """Keep the original wide logo; stack or use ASCII when needed."""
    width = width if width is not None else shutil.get_terminal_size().columns
    encoding = encoding or getattr(sys.stdout, "encoding", None) or "utf-8"
    compact = ASCII_WORDMARK + "\nAWSherlock / AWS security scanner\n"
    if width < max(map(len, compact.splitlines())):
        return "AWSherlock\nAWS security scanner\n" if width >= 20 else "AWSherlock\n"
    try:
        BANNER.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return compact
    if width >= max(map(len, BANNER.splitlines())):
        return BANNER
    portrait = "\n".join(re.split(r" {4,}", line, maxsplit=1)[0].rstrip(" \u2800")
                         for line in BANNER.splitlines())
    return portrait + "\n\n" + compact


def terminal_text(value: str, *, multiline: bool = False) -> str:
    """Show untrusted terminal controls as visible escapes, never instructions."""
    return "".join(
        char if (multiline and char in "\n\t") or unicodedata.category(char) not in {"Cc", "Cf"}
        else char.encode("unicode_escape").decode("ascii")
        for char in value
    )
