# This is a small program that calls checks your current Wireshark version and then calls the tshark program to convert a .pcapng file to a .log file
# This log file is used for a custom PacketParser project.
# This program takes two arguments:   python createLogFile.py inputFile outputFile

import subprocess
import sys
import pandas as pd
from datetime import datetime
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent
remoteServer = ['20.125.112.86', '20.168.32.25', '4.227.88.27', '20.171.48.125', '20.171.48.70', '20.118.171.175', '20.169.20.83']

# Trims the long result of the version call
def wireShark():
    resultStr = evaluateWiresharkVersion()
    wireshark_version = resultStr[10:16]
    return evaluateVersions(wireshark_version)

# Runs the command to pull the Wireshark version
def evaluateWiresharkVersion():
     result = subprocess.run(['wireshark', '--version'], capture_output=True, text=True)
     return result.stdout

# Compares the system's Wireshark version against Version 4.0.13 (known to work with the parser) and directs one of two conversion methods
def evaluateVersions(wireshark_version):
    print("\nYour current Wireshark Version is: ", wireshark_version)
    versionNumbers = wireshark_version.split(".")
    strVersion_array = (versionNumbers)
    intVersion_array = [int(x) for x in strVersion_array]
    knowWorkingVersion = [4, 0, 13]
    if intVersion_array == knowWorkingVersion:
        print("\nYou are using a version of Wireshark known to work with this parser, IP filters are not set; converting to .log with a direct tshark to file call.")
        return False
    else:
        if (intVersion_array[0] > knowWorkingVersion[0]) or ((intVersion_array[0] == knowWorkingVersion[0]) and (intVersion_array[1] > knowWorkingVersion[1])) or ((intVersion_array[0] == knowWorkingVersion[0]) and (intVersion_array[1] == knowWorkingVersion[1]) and (intVersion_array[2] > knowWorkingVersion[2])):
            print("\nYou are using a newer version of Wireshark that may be incompatible with this parser.\nAttempting to reformat that tshark output.\n")
            return False
            
        elif (intVersion_array[0] < knowWorkingVersion[0]) or ((intVersion_array[0] == knowWorkingVersion[0]) and (intVersion_array[1] < knowWorkingVersion[1])) or ((intVersion_array[0] == knowWorkingVersion[0]) and (intVersion_array[1] == knowWorkingVersion[1]) and (intVersion_array[2] < knowWorkingVersion[2])):
            print("\nYou are using an older version of Wireshark that may be incompatible with this parser.\nPlease update your Wireshark installation.")
            return exit()

# Calls the tshark process to convert a .pcapng to a .log file, assuming you have verion 4.0.13 and the Wireshark fields were set appropriately. i.e. No., Time, Data, WorldTime
def convertOldWireshark():
    print("\nAttempting to convert your .pcapng file to a .log file using a tshark call.")
    
   
    tshark_cmd = [
                    'tshark', '-r', inputFile, '-T', 'fields',
                    '-e', '_ws.col.No.', '-e', '_ws.col.Time', '-e', 'data', '-e', '_ws.col.WorldTime'
                ]
    
    with open(outputFile, "w") as log_file:
        result = subprocess.run(tshark_cmd, stdout=log_file, text=True)
    if result.returncode == 0:
        print("Output successfully written to output.log")
    else:
        print("An error occurred while running TShark")

# Starts the process to convert a .pcapng to a .log file using tshark and a number of DataFrame operations.  The input file from Wireshark just needs, No., Time, Data ... so any version should work.
def convertNewWireshark(inputFile):
    print("\nAttempting to convert your .pcapng file to a .log file with No. Time Data WorldTime.\nDepending on the size of the .pcapng, this may take a few minutes.\n")

    tshark_command = [
                    'tshark', '-r', inputFile, '-t', 'ud', '-T', 'fields', 
                    '-e', '_ws.col.No.', '-e', '_ws.col.Time', '-e', 'data',
                    '-e', 'ip.src', "-e", 'ip.dst',
                    '-E', 'separator=,'
                ]
    
    try:
        result = subprocess.run(tshark_command, capture_output=True, text=True)
        lines = result.stdout.splitlines()
        data = [line.split(',') for line in lines if len(line.split(',')) == 5]
    except Exception as e:
        print(f"tshark threw an exception: {e}\n", "exiting...")
        exit()

    short_labels = ['No', 'Time', 'Hexstring', 'Src_IP', 'Des_IP']
    full_df = pd.DataFrame(data, columns=short_labels)
    full_df['WorldTime'] = full_df['Time']
    full_df = full_df[['No', 'Time', 'Hexstring', 'WorldTime', 'Src_IP', 'Des_IP']]
    
    # Finding extraneous packets and removing them
    otherIPs = full_df.loc[(full_df['Src_IP'] != '20.125.112.86') & (full_df['Des_IP'] != '20.125.112.86')] # 
    print("There are ", len(full_df), "rows.\n")
    print("Removing ", len(otherIPs), " rows that are not associated with PROTF.\n")
    full_df = prunningDF(full_df)
    print("There are ", len(full_df), "rows remaining.\n")
    
    print("Replacing the UTC time in column 'Time' with a reference time, while maintain UTC time in column 'WorldTime'\n")
    full_df = to_referenceTime(full_df)

    return full_df

# Drop all rows of packets for those IP addresses that do not contain a Pantheon server.
def prunningDF(full_df):
    full_df = full_df[((full_df['Src_IP'].isin(remoteServer)) | (full_df['Des_IP'].isin(remoteServer)))]
    full_df.reset_index(drop=True, inplace=True)
    return full_df

# Takes the UTC time from the tshark pull with -ud flag and builds a time delta between packets. This should match the "Time" output of Wireshark verion 4.0.13 when complete.
def to_referenceTime(full_df):
    print("Repacing the value in column Time (which is currently UTC Time) with a reference time from the first packet.\n")
    full_df['Time'] = full_df['Time'].apply(to_datetime)
    baseReferenceTime = full_df.loc[0,'Time']
    full_df['Time'] = full_df['Time'] - baseReferenceTime
    full_df['Time'] = full_df['Time'].apply(to_totalsecs)
    return(full_df)

# Standardizes the time input and turns it into a datetime format
def to_datetime(date_string):
    return datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S.%f')

# Changes Formatting
def to_totalsecs(refrenceTime):
    return refrenceTime.total_seconds()

# Removes the columns that were used to calculate the time delta and IP values
def cleanUp(full_df):
    print("Removing the extra columns used for the various functions.")
    final_df = full_df.drop(['Src_IP', 'Des_IP'], axis=1)
    return final_df

n = len(sys.argv)
if n != 3:
    print("This command requires the .pcapng file to be in the same folder as this script.\nAdditionally, two arguments are required.\ni.e. python createLogFile.py example.pcapng new.log")
else:
    inputFile = root_dir / "input" / sys.argv[1]
    outputFile = root_dir / "input" / sys.argv[2]
    if wireShark() == True:
        convertOldWireshark()
    else:
        full_df = convertNewWireshark(inputFile)
        final_df = cleanUp(full_df)
        print("\nSaving the data to the output file.")
        final_df.to_csv(outputFile, header=None, index=None, sep='\t', mode='a')