import subprocess 
import os
import pandas as pd

# tool paths 
# change to necessary paths in the windows 11 file 
evtxECmd = r""
volatility = r""
recMd = r""

#optional output (pdf)

outputDir = r""

os.makedirs(outputDir, exist_ok=True)

