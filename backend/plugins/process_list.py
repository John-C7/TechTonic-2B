import volatility.plugins.common as common
import volatility.utils as utils
import volatility.commands as commands
import volatility.scan as scan
import volatility.win32.tasks as tasks
import volatility.obj as obj

class ProcessList(common.AbstractWindowsCommand):
    """Lists the processes running in the memory dump."""

    def calculate(self):
        # Get the address space (memory space) for the given memory dump
        address_space = utils.load_as(self._config)

        # Use the 'tasks.pslist' plugin to list processes
        for process in tasks.pslist(address_space):
            yield process

    def render_text(self, outfd, data):
        self.table_header(outfd, [
            ("Name", "20"),
            ("PID", "6"),
            ("PPID", "6"),
            ("Thds", "4"),
            ("Hnds", "5"),
            ("Sess", "4"),
            ("Wow64", "5"),
            ("Start", "24")
        ])

        for process in data:
            self.table_row(outfd,
                process.ImageFileName,
                process.UniqueProcessId,
                process.InheritedFromUniqueProcessId,
                process.ActiveThreads,
                process.ObjectTable.HandleCount,
                process.SessionId,
                process.Wow64,
                process.CreateTime or "")
