# coding: utf-8
CMD_DISCOVER=0
CMD_ADOPT=1
CMD_INFORM=2
CMD_NOTIFY=3

class BaseCommand:
    def __init__(self, type=CMD_DISCOVER, data=dict()):
        self.type = type
        self.data = data
    
  