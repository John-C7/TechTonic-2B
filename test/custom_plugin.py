import volatility3.framework.plugins.windows.pslist as pslist

class CustomPsList(pslist.PsList):
    @classmethod
    def get_requirements(cls):
        return []

    def run(self):
        return self.list_processes()
