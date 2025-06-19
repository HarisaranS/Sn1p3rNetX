import os
from datetime import datetime
from pyfiglet import Figlet
from rich.console import Console


console=Console()
log_file=f"logs/scan_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.log"

def printBanner():
    f=Figlet(font='slant')
    console.print(f.renderText("Sn1p3rNetX"),style='bold red')
    

def log(msg):
    os.makedirs("logs",exist_ok=True)
    with open(log_file, "a") as logf:
        logf.write(msg+"\n")
    
def main():
    printBanner()
    log("[*] Sn1p3rNetX+ started!")
    
if __name__== "__main__":
    main()