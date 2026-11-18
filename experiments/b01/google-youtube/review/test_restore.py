"""Check offload restoration with command stubs and no interface changes."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path("experiments/b01/google-youtube/restore-offload.sh")
REPOSITORY = Path(__file__).resolve().parents[4]
SNAPSHOT = (
    "Features for eth0:\n"
    "tcp-segmentation-offload: on\n"
    "\ttx-tcp-mangleid-segmentation: off\n"
    "\ttx-tcp-ecn-segmentation: off [fixed]\n"
    "generic-segmentation-offload: on\n"
)
STUB = r'''
import os
from pathlib import Path
import re
import subprocess
import sys

root = Path(os.environ["STUB_ROOT"])
name = Path(sys.argv[0]).name
with (root / "events").open("a") as stream:
    stream.write(name + " " + " ".join(sys.argv[1:]) + "\n")
if name == "sudo":
    sys.exit(subprocess.run(sys.argv[1:]).returncode)
state = root / "state"
if sys.argv[1] == "-k":
    print(state.read_text(), end="")
else:
    if os.environ["STUB_CASE"] == "failure":
        sys.exit(1)
    feature, value = sys.argv[3:5]
    text = re.sub(r"(?m)^(\s*" + re.escape(feature) + r": )(on|off)",
                  lambda match: match[1] + value, state.read_text())
    if feature == "tcp-segmentation-offload" and value == "on":
        text = text.replace("tx-tcp-mangleid-segmentation: off",
                            "tx-tcp-mangleid-segmentation: on")
    state.write_text(text)
'''


class RestoreTests(unittest.TestCase):
    def test_b01_restore(self):
        for case in ("nested", "parent_and_nested", "failure", "wrong_interface"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / SCRIPT.parent).mkdir(parents=True)
                shutil.copy2(REPOSITORY / SCRIPT, root / SCRIPT)
                artifacts = root / "artifacts/b01-google-youtube-repeat-2026-11"
                artifacts.mkdir(parents=True)
                (artifacts / "offload-before.txt").write_text(SNAPSHOT)
                current = SNAPSHOT.replace("tx-tcp-mangleid-segmentation: off",
                                           "tx-tcp-mangleid-segmentation: on")
                if case == "parent_and_nested":
                    current = current.replace("tcp-segmentation-offload: on",
                                              "tcp-segmentation-offload: off")
                (root / "state").write_text(current)
                commands = root / "commands"
                commands.mkdir()
                dispatcher = commands / "dispatcher"
                dispatcher.write_text("#!" + sys.executable + "\n" + STUB)
                dispatcher.chmod(0o755)
                for name in ("sudo", "ethtool"):
                    (commands / name).symlink_to(dispatcher)
                environment = dict(os.environ, STUB_ROOT=str(root), STUB_CASE=case)
                environment["PATH"] = str(commands) + ":" + os.environ["PATH"]
                interface = "wlo1" if case == "wrong_interface" else "eth0"
                result = subprocess.run(["bash", str(SCRIPT), interface], cwd=root,
                                        env=environment, text=True, capture_output=True)
                if case in ("nested", "parent_and_nested"):
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual((root / "state").read_text(), SNAPSHOT)
                    self.assertTrue((artifacts / "offload-restored.txt").exists())
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse((artifacts / "offload-restored.txt").exists())
                if case == "wrong_interface":
                    self.assertFalse((root / "events").exists())


if __name__ == "__main__":
    unittest.main()
