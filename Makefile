all:

observe:
    sudo python observe.py -a
    
action:
    sudo python action.py -a
    
req:
    dig @129.104.201.53 radius.polytechnique.fr
    
badreq:
    dig @129.104.221.86 radius.polytechnique.fr
