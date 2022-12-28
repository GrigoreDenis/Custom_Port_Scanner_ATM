class logger:
    def __init__(self,level):
        self.log_level = level
    def log(self,string):
        if self.log_level ==1:
            print("LOG: %s" % string)