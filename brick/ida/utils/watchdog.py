from threading import Timer

class Watchdog(Exception):
    def __init__(self, timeout, userHandler=None):
        self.timeout = timeout
        self.handler = userHandler if userHandler is not None else self.defaultHandler
        self.timer = Timer(self.timeout, self.handler)

    def __enter__(self):
        self.timer.start()
  
    def __exit__(self, type, value, traceback):
        self.timer.cancel()
    
    def defaultHandler(self):
        raise TimeoutError(f"The code took more than {self.timeout} seconds to complete")
        