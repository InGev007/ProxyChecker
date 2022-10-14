import random

def randomua():
    with open("./useragent.txt", "rt") as file:
        lines=file.readlines()
    file.close()
    s=lines[random.randint(0,999)]
    s=s.rstrip('\n')
    otvet={}
    otvet['User-Agent']=s
    return otvet