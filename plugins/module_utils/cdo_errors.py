class CDODeviceExists(Exception):
    def __init__(self, message, errors):
        self.message = message
        super().__init__(self.message)
