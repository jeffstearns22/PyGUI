'''
Created on Dec 20, 2022

@author: Jeff Stearns
'''

import array
import pyshark
import time
import logging
import struct
import PySimpleGUI as sg	#Tkinter base GUI, Python 3
#import PySimpleGUI27 as sg	#Tkinter base GUI, Python 2
#import trollius			#Python 2

from ctypes import *
from datetime import datetime

#Setup GUI theme and font
#sg.theme('DarkTanBlue')		#Python3
sg.ChangeLookAndFeel('DarkTanBlue')	#Python2
wfont=("liberation mono",16)	#Mono space font family
sg.set_options(font=wfont)

'''
=====================================================================================================
# Function to Check Status Word for Errors : Array of bit locations, statuserr, and integer status
# word, statusint, passed in. Selected bit locations compared to '0', no error.
=====================================================================================================
'''
def status_check(statuserr,statusint):
    errchk = 0
    bitlen = len(statuserr)
    binstat = format(statusint,'#034b')
    #Remove first 2 characters, '0b'
    binstat=binstat[2:]
    for x in range(bitlen):
        bitloc = binstat[31 - statuserr[x]]	#Pick off selected bit, with MSB first (left)
        if (bitloc != '0'):
            print("Status word error detected, bit %d failed." % statuserr[x])
            errchk=1
    return errchk

'''
=====================================================================================================
# Function to Convert hex string to Floating number
=====================================================================================================
'''
def ahex2float(s):
    i = int(s,16)			# convert from hex to python int
    cp = pointer(c_int(i))		# make into a C integer
    fp = cast(cp,POINTER(c_float))	# cast int pointer to float pointer
    return fp.contents.value		# dereference the pointer, get the float

'''
=====================================================================================================
# Run live capture on selected sensor
=====================================================================================================
'''
class pysharklive():
    def __init__(self,interface,outfile,sensor,timeout,pkt_int_time,pcap_out,csv_out):
        self.interface=interface
        self.outfile=outfile
        self.sensor=sensor		# dhsyl(1,2), ddd(1,2), gyro
        self.timeout=timeout		# number of minutes
        self.pkt_int_time=pkt_int_time	# Packet interval time violation
        self.pcap_out=pcap_out		# Generate pyshark.pcap output file
        self.csv_out=csv_out		# Generate sensor.csv output file

        # Setup TCP ports by Sensor selected
        if (self.sensor == "dhsyl1"):		#Digital High Speed Log 1
            tcpfilter = "tcp dst port 2750"
        elif (self.sensor == "dhsyl2"):		#Digital High Speed Log 2
            tcpfilter = "tcp dst port 2760"
        elif (self.sensor == "ddd1"):		#Digital Depth Detector 1
            tcpfilter = "tcp dst port 2770"
        elif (self.sensor == "ddd2"):		#Digital Depth Detector 2
            tcpfilter = "tcp dst port 2780"
        elif (self.sensor == "gyro"):		#Gyro Data
            tcpfilter = "tcp dst port 8125"
        elif (self.sensor == "ndm"):		#Navigation Data Message Data
            tcpfilter = "tcp dst port 60010"
        elif (self.sensor == "sdm"):		#Ship Data Message Data
            tcpfilter = "tcp dst port 60012"

        # Get Start time for filename
        start = time.localtime()

        # Open packet error log
        #err_fname = 'Packet_Error_{0}{1:02d}{2:02d}_{3:02d}{4:02d}.csv'.format(start.tm_year,start.tm_mon,start.tm_mday,start.tm_hour,start.tm_min)
        err_fname = 'Packet_Error.log'
        filesde = open(err_fname,'w')

        print('\nCapturing on %s...\n' % self.interface)

        snifftim = "0.0"

        # Get Start time for Timeout in epoch seconds
        start = time.time()

        # Setup to capture packets
        if (self.pcap_out == True):
            cap = pyshark.LiveCapture(interface = self.interface,output_file = self.outfile,bpf_filter=tcpfilter)
        else:
            cap = pyshark.LiveCapture(interface = self.interface,bpf_filter=tcpfilter)

        # Initialize counter for number of Packet Interval timeouts detected
        pkt_interr_cnt = 0
        # Initialize counter for number of Checksum Errors detected
        chksum_err_cnt = 0
        # Initialize counter for number of Status Errors detected
        status_err_cnt = 0

        # Zero out delta time for first packet
        first_packet = True
        # Initialize Max Packet Interval Time
        max_pkt_tim = 0

        # Initialize running packet counter value
        packet_counter = 0
        # Use timeout in minutes
        timeout_sec = self.timeout * 60		# Convert minutes to seconds
        # Set self.pkt_count to maximum
        self.pkt_count = 8589934591

        # Launch output window to display live capture results, Python3
        if (self.sensor == "dhsyl1" or self.sensor == "dhsyl2"):
            window = setup_outputwindow("EMWTRSPD","BLNDWSPD","DISTANCE",self.sensor)
            window.refresh()
            time.sleep(30)
        if (self.sensor == "ddd1" or self.sensor == "ddd2"):
            window = setup_outputwindow("DEPTH","DEPTHVEL","DEPTHACC",self.sensor)
        if (self.sensor == "gyro"):
            window = setup_outputwindow("HEADING","ROLL","PITCH",self.sensor)
        if (self.sensor == "ndm"):
            window = setup_outputwindow("VELOCITY","DEPTH","HEADING",self.sensor)
        if (self.sensor == "sdm"):
            window = setup_outputwindow("EMLOG1","DDD1","GYRO",self.sensor)

        #Setup csv file for sensor data capture if enabled
        if (self.csv_out == True):
            #fname = '{0}_{1}{2:02d}{3:02d}_{4:02d}{5:02d}.csv'.format(self.sensor,start.tm_year,start.tm_mon,start.tm_mday,start.tm_hour,start.tm_min)
            fname = '{0}.csv'.format(self.sensor)
            filesd = open(fname,'w')        
            # Store capture start time at beginning of CSV file
            csv_timestamp = ("%s\n"%time.asctime(time.localtime(time.time())))

        for packet in cap.sniff_continuously(packet_count=self.pkt_count):
            try:
                localtime = time.asctime(time.localtime(time.time()))
                protocol = packet.transport_layer       # protocol type
                src_addr = packet.ip.src                # source address
                src_port = packet[protocol].srcport     # source port
                dst_addr = packet.ip.dst                # destination address
                dst_port = packet[protocol].dstport     # destination port
                payload  = packet.tcp.payload
                laststim = snifftim			# Store last sniff time for delta measurement
                snifftim = packet.sniff_timestamp
                pllen    = len(payload)
                now      = time.time()
                elapsed_time = now - start
                # Advance packet counter
                packet_counter += 1

                laststimi = float(laststim)
                snifftimi = float(snifftim)
                if (first_packet == True):
                    deltatim = 0
                else:
                    deltatim = snifftimi - laststimi
                drop_packet=False
                # If deltatim is less than 0.1 msec, drop packet, CNSTLSIM VAX Simulator duplicates packets
                if (first_packet == False):
                    if (deltatim < 0.0001):
                        drop_packet=True
                first_packet = False
                if (deltatim > max_pkt_tim):
                    max_pkt_tim = deltatim	# Track biggest packet interval gap
                print("Delta Time between packets %f" % deltatim)
                if (deltatim > self.pkt_int_time):
                    print("ERROR : Packet time interval exceeded => ",deltatim)
                    error_string=("At time: %s, Time Interval of %f exceeded, Time Interval %f detected.\n" % (localtime,self.pkt_int_time,deltatim))
                    filesde.write(error_string)
                    pkt_interr_cnt += 1
                    #window['WARNING'].update('WARNING PACKET TIMEOUT DETECTED {:d} TIMES'.format(pkt_interr_cnt))

                # output packet info
                print("%s %s:%s <-> %s:%s (%s)" % (localtime, src_addr, src_port, dst_addr, dst_port, protocol))
                print("%d" % pllen)
                #print("%s" % payload)

                # Split payload into string array
                plbytes = payload.split(':')
                if ((self.sensor == "dhsyl1" or self.sensor == "dhsyl2") and drop_packet == False):
                    # Write out fields with data, all other fields are always 0
                    if (packet_counter == 1 and self.csv_out == True):
                        filesd.write("SYSTATS1,SYSTATS2,EMWTRSPD,BLNDWSPD,DISTANCE,CHECKSUM,DELTATIM\n")
                    # Pack 108 bytes into output_buffer, 108 chars
                    output_buffer = bytes()
                    for x in range(108):
                        # List of strings must be converted to bytes object prior to packing
                        bytebuffer = bytes(plbytes[x],'ascii')
                        output_buffer = struct.pack("2s",bytebuffer)
                    # Extract DHSYL data from struct
                    SYSTATUS1,        = struct.unpack_from("8s", output_buffer, offset=0)
                    SYSTATUS2,        = struct.unpack_from("8s", output_buffer, offset=8)
                    DPLSTATUS,        = struct.unpack_from("8s", output_buffer, offset=16)
                    BTMFVEL,          = struct.unpack_from("8s", output_buffer, offset=24)
                    BTMAVEL,          = struct.unpack_from("8s", output_buffer, offset=32)
                    BTMVVEL,          = struct.unpack_from("8s", output_buffer, offset=40)
                    BTMSPD,           = struct.unpack_from("8s", output_buffer, offset=48)
                    BTMRNG1,          = struct.unpack_from("8s", output_buffer, offset=56)
                    BTMRNG2,          = struct.unpack_from("8s", output_buffer, offset=64)
                    BTMRNG3,          = struct.unpack_from("8s", output_buffer, offset=72)
                    BTMRNG4,          = struct.unpack_from("8s", output_buffer, offset=80)
                    BTMDST,           = struct.unpack_from("8s", output_buffer, offset=88)
                    WTRFVEL,          = struct.unpack_from("8s", output_buffer, offset=96)
                    WTRAVEL,          = struct.unpack_from("8s", output_buffer, offset=104)
                    WTRVVEL,          = struct.unpack_from("8s", output_buffer, offset=112)
                    DPLWTRSPD,        = struct.unpack_from("8s", output_buffer, offset=120)
                    DPLSENSC,         = struct.unpack_from("8s", output_buffer, offset=128)
                    EMWaterSpeedS,    = struct.unpack_from("8s", output_buffer, offset=136)
                    BlendWaterSpeedS, = struct.unpack_from("8s", output_buffer, offset=144)
                    distances,        = struct.unpack_from("8s", output_buffer, offset=152)
                    WTEMP,            = struct.unpack_from("8s", output_buffer, offset=160)
                    DOPP_ROLL,        = struct.unpack_from("8s", output_buffer, offset=168)
                    DOPP_PITCH,       = struct.unpack_from("8s", output_buffer, offset=176)
                    DOPP_HDG,         = struct.unpack_from("8s", output_buffer, offset=184)
                    UPDRATE,          = struct.unpack_from("8s", output_buffer, offset=192)
                    RSV,              = struct.unpack_from("8s", output_buffer, offset=200)
                    
                    # Setup array to select STATUS bits to verify
                    #statuserr = array.array('I',[23,24,25,26,27])
                    statuserr = array.array('I',[26])
                    # Check SYSTATUS1, EM Water Speed Log Invalid bit
                    errchk = status_check(statuserr,int(SYSTATUS1,16))
                    if (errchk):
                        status_err_cnt += 1
                        error_string=("At time: %s, %s SYSTATUS1 error, bit %d EM_SENSOR_SPEED_INVALID failed.\n" % (localtime,self.sensor,statuserr[0]))
                        filesde.write(error_string)
                        window['STATUS'].update('WARNING STATUS ERROR DETECTED {:d} TIMES'.format(status_err_cnt))
                    
                    # Convert displayed parameters to FLOAT from Ascii Hex String format
                    EMWaterSpeed = ahex2float(EMWaterSpeedS)
                    BlendWaterSpeed = ahex2float(BlendWaterSpeedS)
                    distance = ahex2float(distances)
                    
                    # Generate Checksum
                    checksum_calc = int(SYSTATUS1,16) + int(SYSTATUS2,16) + int(DPLSTATUS,16) + int(BTMFVEL,16) + int(BTMAVEL,16) + int(BTMVVEL,16) + int(BTMSPD,16) + int(BTMRNG1,16) + int(BTMRNG2,16) + int(BTMRNG3,16) + int(BTMRNG4,16) + int(BTMDST,16) + int(WTRFVEL,16) + int(WTRAVEL,16) + int(WTRVVEL,16) + int(DPLWTRSPD,16) + int(DPLSENSC,16) + int(EMWaterSpeeds,16) + int(BlendWaterSpeeds,16) + int(distances,16) + int(WTEMP,16) + int(DOPP_ROLL,16) + int(DOPP_PITCH,16) + int(DOPP_HDG,16) + int(UPDRATE,16) + int(RSV,16)
                    # If calculated checksum rolls over max value, truncate
                    checksum_calc = checksum_calc % 0x100000000
                    
                    checksum,         = struct.unpack_from("8s", output_buffer, offset=208)
                    
                    # Compare Calculated Checksum with Read Checksum
                    if (checksum_calc != int(checksum,16)):
                        chksum_err_cnt += 1
                        #print('Checksum error detected')
                        error_string=("At time: %s, checksum error, expected %08x, detected %08x.\n" % (localtime,checksum_clac,int(checksum,16)))
                        filesde.write(error_string)
                        window['CHECKSUM'].update('WARNING CHECKSUM ERROR DETECTED {:d} TIMES'.format(chksum_err_cnt))

                    # Setup formatted csv string to write to output file, convert bytes to string with decode
                    csv_string = ("%s,%s,%2.5f,%2.5f,%1.6f,%s,%1.6f\n" % (SYSTATUS1.decode(),SYSTATUS2.decode(),EMWaterSpeed,
                                                                    BlendWaterSpeed,distance,checksum.decode(),deltatim))
                    if (self.csv_out == True):
                        filesd.write(csv_string)
                    # Display live capture results to output window
                    window['PARM1'].update('{:3.5f}'.format(EMWaterSpeed))
                    window['PARM2'].update('{:3.5f}'.format(BlendWaterSpeed))
                    window['PARM3'].update('{:3.5f}'.format(distance))
                    window['DLTTIM'].update('{:3.5f}'.format(deltatim))
                    window['MAXTIM'].update('{:3.5f}'.format(max_pkt_tim))
                    window['PKTCNT'].update(packet_counter)
                    window['ELPTIM'].update('{:3.5f}'.format(elapsed_tim))
                    window.refresh()
                if ((self.sensor == "ddd1" or self.sensor == "ddd2") and drop_packet == False):
                    # Write out selected fields
                    if (packet_counter == 1 and self.csv_out == True):
                        filesd.write("SOM,SYSINFO,SYSPM,SENSORID,DEPTH,DEPTHVEL,DEPTHACC,DEPTHVALID,RES1,RES2,RES3,CHECKSUM,DELTATIM\n")
                    # Pack 48 bytes into output_buffer, 48 chars
                    output_buffer = bytes()
                    for x in range(48):
                        # List of strings must be converted to bytes object prior to packing
                        bytebuffer = bytes(plbytes[x],'ascii')
                        output_buffer = struct.pack("2s",bytebuffer)
                    # Extract DDD data from struct
                    SOM,            = struct.unpack_from("8s", output_buffer, offset=0)
                    SYSINFO,        = struct.unpack_from("8s", output_buffer, offset=8)
                    SYSPM,          = struct.unpack_from("8s", output_buffer, offset=16)
                    SENSORID,       = struct.unpack_from("8s", output_buffer, offset=24)
                    DEPTHS,         = struct.unpack_from("8s", output_buffer, offset=32)
                    DEPTHVELS,      = struct.unpack_from("8s", output_buffer, offset=40)
                    DEPTHACCS,      = struct.unpack_from("8s", output_buffer, offset=48)
                    DEPTHVALID,     = struct.unpack_from("8s", output_buffer, offset=56)
                    RES1,           = struct.unpack_from("8s", output_buffer, offset=64)
                    RES2,           = struct.unpack_from("8s", output_buffer, offset=72)
                    RES3,           = struct.unpack_from("8s", output_buffer, offset=80)
                    
                    # Setup array to select STATUS bits to verify
                    #statuserr = array.array('I',[26])
                    #errchk = status_check(statuserr,int(SYSINFO,16))
                    #if (errchk):
                    #    status_err_cnt += 1
                    #    error_string=("At time: %s, %s SYSINFO error, bit %d xxx failed.\n" % (localtime,self.sensor,statuserr[0]))
                    #    filesde.write(error_string)
                    #    window['STATUS'].update('WARNING STATUS ERROR DETECTED {:d} TIMES'.format(status_err_cnt))
                    
                    # Convert displayed parameters to FLOAT from Ascii Hex String format
                    depth = ahex2float(DEPTHS)
                    depthvel = ahex2float(DEPTHVELS)
                    depthacc = ahex2float(DEPTHACCS)
                    
                    # Generate Checksum
                    checksum_calc = int(SOM,16) + int(SYSINFO,16) + int(SYSPM,16) + int(SENSORID,16) + int(DEPTHS,16) + int(DEPTHVELS,16) + int(DEPTHACCS,16) + int(DEPTHVALID,16) + int(RES1,16) + int(RES2,16) + int(RES3,16)
                    # If calculated checksum rolls over max value, truncate
                    checksum_calc = checksum_calc % 0x100000000
                    
                    checksum,         = struct.unpack_from("8s", output_buffer, offset=88)
                    
                    # Compare Calculated Checksum with Read Checksum
                    if (checksum_calc != int(checksum,16)):
                        chksum_err_cnt += 1
                        #print('Checksum error detected')
                        error_string=("At time: %s, checksum error, expected %08x, detected %08x.\n" % (localtime,checksum_clac,int(checksum,16)))
                        filesde.write(error_string)
                        window['CHECKSUM'].update('WARNING CHECKSUM ERROR DETECTED {:d} TIMES'.format(chksum_err_cnt))

                    # Setup formatted csv string to write to output file, convert bytes to string with decode
                    csv_string = ("%s,%s,%s,%s,%2.5f,%2.5f,%1.6f,%s,%s,%s,%s,%s,%1.6f\n" % (SOM.decode(),SYSINFO.decode(),
                                    SYSPM.decode(),SENSORID.decode(),depth,depthvel,depthacc,DEPTHVALID.decode(),RES1.decode(),
				    RES2.decode(),RES3.decode(),checksum.decode(),deltatim))
                    if (self.csv_out == True):
                        filesd.write(csv_string)
                    # Display live capture results to output window
                    window['PARM1'].update('{:3.5f}'.format(depth))
                    window['PARM2'].update('{:3.5f}'.format(depthvel))
                    window['PARM3'].update('{:3.5f}'.format(depthacc))
                    window['DLTTIM'].update('{:3.5f}'.format(deltatim))
                    window['MAXTIM'].update('{:3.5f}'.format(max_pkt_tim))
                    window['PKTCNT'].update(packet_counter)
                    window['ELPTIM'].update('{:3.5f}'.format(elapsed_tim))
                    window.refresh()
                if ((self.sensor == "gyro") and drop_packet == False):
                    # Write out selected fields
                    if (packet_counter == 1 and self.csv_out == True):
                        filesd.write("SOM,SYSMODE,DATAVALID,SYSPM,IMUSTAT,TAGSEC,TAGMSEC,HEADING,ROLL,PITCH,HRATE,RRATE,PRATE,HSTDDEV,RSTDDEV,PSTDDEV,SYSPM2,RES1,RES2,RES3,RES4,CHECKSUM,DELTATIM\n")
                    # Pack 88 bytes into output_buffer, 88 chars
                    output_buffer = bytes()
                    for x in range(88):
                        # List of strings must be converted to bytes object prior to packing
                        bytebuffer = bytes(plbytes[x],'ascii')
                        output_buffer = struct.pack("2s",bytebuffer)
                    # Extract GYRO data from struct
                    SOM,            = struct.unpack_from("8s", output_buffer, offset=0)
                    SYSMODE,        = struct.unpack_from("8s", output_buffer, offset=8)
                    DATAVALID,      = struct.unpack_from("8s", output_buffer, offset=16)
                    SYSPM,          = struct.unpack_from("8s", output_buffer, offset=24)
                    IMUSTAT,        = struct.unpack_from("8s", output_buffer, offset=32)
                    TAGSEC,         = struct.unpack_from("8s", output_buffer, offset=40)
                    TAGMSEC,        = struct.unpack_from("8s", output_buffer, offset=48)
                    HEADINGS,       = struct.unpack_from("8s", output_buffer, offset=56)
                    ROLLS,          = struct.unpack_from("8s", output_buffer, offset=64)
                    PITCHS,         = struct.unpack_from("8s", output_buffer, offset=72)
                    HRATES,         = struct.unpack_from("8s", output_buffer, offset=80)
                    RRATES,         = struct.unpack_from("8s", output_buffer, offset=88)
                    PRATES,         = struct.unpack_from("8s", output_buffer, offset=96)
                    HSTDDEVS,       = struct.unpack_from("8s", output_buffer, offset=104)
                    RSTDDEVS,       = struct.unpack_from("8s", output_buffer, offset=112)
                    PSTDDEVS,       = struct.unpack_from("8s", output_buffer, offset=120)
                    SYSPM2,         = struct.unpack_from("8s", output_buffer, offset=128)
                    RES1,           = struct.unpack_from("8s", output_buffer, offset=136)
                    RES2,           = struct.unpack_from("8s", output_buffer, offset=144)
                    RES3,           = struct.unpack_from("8s", output_buffer, offset=152)
                    RES4,           = struct.unpack_from("8s", output_buffer, offset=160)
                    
                    # Setup array to select STATUS bits to verify
                    #statuserr = array.array('I',[26])
                    #errchk = status_check(statuserr,int(SYSMODE,16))
                    #if (errchk):
                    #    status_err_cnt += 1
                    #    error_string=("At time: %s, %s SYSMODE error, bit %d xxx failed.\n" % (localtime,self.sensor,statuserr[0]))
                    #    filesde.write(error_string)
                    #    window['STATUS'].update('WARNING STATUS ERROR DETECTED {:d} TIMES'.format(status_err_cnt))
                    
                    # Convert displayed parameters to FLOAT from Ascii Hex String format
                    heading = ahex2float(HEADINGS)
                    roll    = ahex2float(ROLLS)
                    pitch   = ahex2float(PITCHS)
                    hrate   = ahex2float(HRATES)
                    rrate   = ahex2float(RRATES)
                    prate   = ahex2float(PRATES)
                    hstddev = ahex2float(HSTDDEVS)
                    rstddev = ahex2float(RSTDDEVS)
                    pstddev = ahex2float(PSTDDEVS)
                    
                    # Generate Checksum
                    checksum_calc = int(SOM,16) + int(SYSMODE,16) + int(DATAVALID,16) + int(SYSPM,16) + int(IMUSTAT,16) + int(TAGSEC,16) + int(TAGMSEC,16) + int(HEADINGS,16) + int(ROLLS,16) + int(PITCHS,16) + int(HRATES,16) + int(RRATES,16) + int(PRATES,16) + int(HSTDDEVS,16) + int(RSTDDEVS,16) + int(PSTDDEVS,16) + int(SYSPM2,16) + int(RES1,16) + int(RES2,16) + int(RES3,16) + int(RES4,16)
                    # If calculated checksum rolls over max value, truncate
                    checksum_calc = checksum_calc % 0x100000000
                    
                    checksum,         = struct.unpack_from("8s", output_buffer, offset=168)
                    
                    # Compare Calculated Checksum with Read Checksum
                    if (checksum_calc != int(checksum,16)):
                        chksum_err_cnt += 1
                        #print('Checksum error detected')
                        error_string=("At time: %s, checksum error, expected %08x, detected %08x.\n" % (localtime,checksum_clac,int(checksum,16)))
                        filesde.write(error_string)
                        window['CHECKSUM'].update('WARNING CHECKSUM ERROR DETECTED {:d} TIMES'.format(chksum_err_cnt))

                    # Setup formatted csv string to write to output file, convert bytes to string with decode
                    csv_string = ("%s,%s,%s,%s,%s,%s,%s,%2.5f,%2.5f,%1.6f,%2.5f,%2.5f,%1.6f,%2.5f,%2.5f,%1.6f,%s,%s,%s,%s,%s,%s,%1.6f\n" % 
				    (SOM.decode(),SYSMODE.decode(),DATAVALID.decode(),SYSPM.decode(),IMUSTAT.decode(),TAGSEC.decode(),TAGMSEC.decode(),
				    heading,roll,pitch,hrate,rrate,prate,hstddev,rstddev,pstddev,SYSPM2.decode(),RES1.decode(),
				    RES2.decode(),RES3.decode(),RES4.decode(),checksum.decode(),deltatim))
                    if (self.csv_out == True):
                        filesd.write(csv_string)
                    # Display live capture results to output window
                    window['PARM1'].update('{:3.5f}'.format(heading))
                    window['PARM2'].update('{:3.5f}'.format(roll))
                    window['PARM3'].update('{:3.5f}'.format(pitch))
                    window['DLTTIM'].update('{:3.5f}'.format(deltatim))
                    window['MAXTIM'].update('{:3.5f}'.format(max_pkt_tim))
                    window['PKTCNT'].update(packet_counter)
                    window['ELPTIM'].update('{:3.5f}'.format(elapsed_tim))
                    window.refresh()
                if ((self.sensor == "sdm") and drop_packet == False):
                    # Write out selected fields
                    if (packet_counter == 1 and self.csv_out == True):
                        filesd.write("EMLOG1,EMLOG2,OSD1,OSD2,GYRO,FMCT,SIW,DELTATIM\n")
                    # Pack 320 bytes into output_buffer, 320 chars
                    output_buffer = bytes()
                    for x in range(320):
                        # List of strings must be converted to bytes object prior to packing
                        bytebuffer = bytes(plbytes[x],'ascii')
                        output_buffer = struct.pack("2s",bytebuffer)
                    # Extract DDD data from struct
                    MSGID,        = struct.unpack_from("8s", output_buffer, offset=0)
                    SEQNUM,       = struct.unpack_from("8s", output_buffer, offset=8)
                    SPAREW0,      = struct.unpack_from("16s", output_buffer, offset=16)
                    BLKID,        = struct.unpack_from("8s", output_buffer, offset=32)
                    SPAREW1,      = struct.unpack_from("8s", output_buffer, offset=40)
                    OSS1S,        = struct.unpack_from("16s", output_buffer, offset=48)
                    OSS2S,        = struct.unpack_from("16s", output_buffer, offset=64)
                    OSD1S,        = struct.unpack_from("16s", output_buffer, offset=80)
                    OSD2S,        = struct.unpack_from("16s", output_buffer, offset=96)
                    GSHS,         = struct.unpack_from("16s", output_buffer, offset=112)
                    FMCTS,        = struct.unpack_from("8s", output_buffer, offset=128)
                    SPAREW2,      = struct.unpack_from("168s", output_buffer, offset=136)
                    SIW,          = struct.unpack_from("8s", output_buffer, offset=304)
                    ECWSDM,       = struct.unpack_from("8s", output_buffer, offset=312)
                   
                    # Setup array to select STATUS bits to verify
                    #statuserr = array.array('I',[26])
                    #errchk = status_check(statuserr,int(SYSINFO,16))
                    #if (errchk):
                    #    status_err_cnt += 1
                    #    error_string=("At time: %s, %s SYSINFO error, bit %d xxx failed.\n" % (localtime,self.sensor,statuserr[0]))
                    #    filesde.write(error_string)
                    #    window['STATUS'].update('WARNING STATUS ERROR DETECTED {:d} TIMES'.format(status_err_cnt))
                    
                    # Convert displayed parameters to FLOAT from Ascii Hex String format
                    oss1 = ahex2float(OSS1S)
                    oss2 = ahex2float(OSS2S)
                    osd1 = ahex2float(OSD1S)
                    osd2 = ahex2float(OSD2S)
                    gsh  = ahex2float(GSHS)
                    fmct = ahex2float(FMCTS)
                    
                    # Generate Checksum
                    #checksum_calc = int(SOM,16) + int(SYSINFO,16) + int(SYSPM,16) + int(SENSORID,16) + int(DEPTHS,16) + int(DEPTHVELS,16) + int(DEPTHACCS,16) + int(DEPTHVALID,16) + int(RES1,16) + int(RES2,16) + int(RES3,16)
                    # If calculated checksum rolls over max value, truncate
                    #checksum_calc = checksum_calc % 0x100000000
                    
                    #checksum,         = struct.unpack_from("8s", output_buffer, offset=88)
                    
                    # Compare Calculated Checksum with Read Checksum
                    #if (checksum_calc != int(checksum,16)):
                    #    chksum_err_cnt += 1
                        #print('Checksum error detected')
                    #    error_string=("At time: %s, checksum error, expected %08x, detected %08x.\n" % (localtime,checksum_clac,int(checksum,16)))
                    #    filesde.write(error_string)
                    #    window['CHECKSUM'].update('WARNING CHECKSUM ERROR DETECTED {:d} TIMES'.format(chksum_err_cnt))

                    # Setup formatted csv string to write to output file, convert bytes to string with decode
                    csv_string = ("%2.5f,%2.5f,%2.5f,%2.5f,%2.5f,%2.5f,%s\n" % (oss1,oss2,osd1,osd2,gsh,fmct,SIW.decode(),deltatim))
                    if (self.csv_out == True):
                        filesd.write(csv_string)
                    # Display live capture results to output window
                    window['PARM1'].update('{:3.5f}'.format(oss1))
                    window['PARM2'].update('{:3.5f}'.format(osd1))
                    window['PARM3'].update('{:3.5f}'.format(gsh))
                    window['DLTTIM'].update('{:3.5f}'.format(deltatim))
                    window['MAXTIM'].update('{:3.5f}'.format(max_pkt_tim))
                    window['PKTCNT'].update(packet_counter)
                    window['ELPTIM'].update('{:3.5f}'.format(elapsed_tim))
                    window.refresh()
                if ((self.sensor == "ndm") and drop_packet == False):
                    # Write out selected fields
                    if (packet_counter == 1 and self.csv_out == True):
                        filesd.write("HEADING,PITCH,ROLL,VELN,VELE,VELV,LAT,LONG,DEPTH,NIWN1,NIWN2,GPSLAT,GPSLON,GPSFOM,DBK,DELTATIM\n")
                    # Pack 1056 bytes into output_buffer
                    output_buffer = bytes()
                    for x in range(1056):
                        # List of strings must be converted to bytes object prior to packing
                        bytebuffer = bytes(plbytes[x],'ascii')
                        output_buffer = struct.pack("2s",bytebuffer)
                    # Extract DDD data from struct
                    MSGID,        = struct.unpack_from("8s", output_buffer, offset=0)
                    SEQNUM,       = struct.unpack_from("8s", output_buffer, offset=8)
                    SPAREW0,      = struct.unpack_from("16s", output_buffer, offset=16)
                    BLKID0,       = struct.unpack_from("8s", output_buffer, offset=32)
                    YEAR,         = struct.unpack_from("8s", output_buffer, offset=40)
                    TODDAY,       = struct.unpack_from("8s", output_buffer, offset=48)
                    TODHR,        = struct.unpack_from("8s", output_buffer, offset=56)
                    TODMIN,       = struct.unpack_from("8s", output_buffer, offset=64)
                    TODSEC,       = struct.unpack_from("8s", output_buffer, offset=72)
                    STM,          = struct.unpack_from("8s", output_buffer, offset=80)
                    GPSTIME,      = struct.unpack_from("8s", output_buffer, offset=88)
                    DTGPS,        = struct.unpack_from("8s", output_buffer, offset=96)
                    SPAREW1,      = struct.unpack_from("104s", output_buffer, offset=104)
                    NIWN1,        = struct.unpack_from("8s", output_buffer, offset=208)
                    ECWN1,        = struct.unpack_from("8s", output_buffer, offset=216)
                    BLKID1,       = struct.unpack_from("8s", output_buffer, offset=224)
                    SPAREW2,      = struct.unpack_from("8s", output_buffer, offset=232)
                    HeadingS,     = struct.unpack_from("16s", output_buffer, offset=240)
                    PitchS,       = struct.unpack_from("16s", output_buffer, offset=256)
                    RollS,        = struct.unpack_from("16s", output_buffer, offset=272)
                    VelnS,        = struct.unpack_from("16s", output_buffer, offset=288)
                    VeleS,        = struct.unpack_from("16s", output_buffer, offset=304)
                    VelvS,        = struct.unpack_from("16s", output_buffer, offset=320)
                    LatS,         = struct.unpack_from("16s", output_buffer, offset=336)
                    LongS,        = struct.unpack_from("16s", output_buffer, offset=352)
                    OsdS,         = struct.unpack_from("16s", output_buffer, offset=368)
                    SPAREW3,      = struct.unpack_from("128s", output_buffer, offset=384)
                    NIWN2,        = struct.unpack_from("8s", output_buffer, offset=512)
                    ECWN2,        = struct.unpack_from("8s", output_buffer, offset=520)
                    BLKID2,       = struct.unpack_from("8s", output_buffer, offset=528)
                    CONYEAR,      = struct.unpack_from("8s", output_buffer, offset=536)
                    CONDAY,       = struct.unpack_from("8s", output_buffer, offset=544)
                    CONHOUR,      = struct.unpack_from("8s", output_buffer, offset=552)
                    CONMIN,       = struct.unpack_from("8s", output_buffer, offset=560)
                    CONSEC,       = struct.unpack_from("8s", output_buffer, offset=568)
                    GPSlatS,      = struct.unpack_from("16s", output_buffer, offset=576)
                    GPSlonS,      = struct.unpack_from("16s", output_buffer, offset=592)
                    GPSfomS,      = struct.unpack_from("8s", output_buffer, offset=608)
                    SPAREW4,      = struct.unpack_from("8s", output_buffer, offset=616)
                    BINSH,        = struct.unpack_from("16s", output_buffer, offset=624)
                    BINSP,        = struct.unpack_from("16s", output_buffer, offset=640)
                    BINSR,        = struct.unpack_from("16s", output_buffer, offset=656)
                    BINSVN,       = struct.unpack_from("16s", output_buffer, offset=672)
                    BINSVE,       = struct.unpack_from("16s", output_buffer, offset=688)
                    BINSVV,       = struct.unpack_from("16s", output_buffer, offset=704)
                    BINSLAT,      = struct.unpack_from("16s", output_buffer, offset=720)
                    BINSLON,      = struct.unpack_from("16s", output_buffer, offset=736)
                    DbkS,         = struct.unpack_from("16s", output_buffer, offset=752)
                    BTHYEAR,      = struct.unpack_from("8s", output_buffer, offset=768)
                    BTHDAY,       = struct.unpack_from("8s", output_buffer, offset=776)
                    BTHHOUR,      = struct.unpack_from("8s", output_buffer, offset=784)
                    BTHMIN,       = struct.unpack_from("8s", output_buffer, offset=792)
                    BTHSEC,       = struct.unpack_from("8s", output_buffer, offset=800)
                    SPAREW5,      = struct.unpack_from("8s", output_buffer, offset=808)
                    BTHLAT,       = struct.unpack_from("16s", output_buffer, offset=816)
                    BTHLON,       = struct.unpack_from("16s", output_buffer, offset=832)
                    SPAREW6,      = struct.unpack_from("176s", output_buffer, offset=848)
                    NIWN6,        = struct.unpack_from("8s", output_buffer, offset=1024)
                    ECWN6,        = struct.unpack_from("8s", output_buffer, offset=1032)
                    BLKID3,       = struct.unpack_from("8s", output_buffer, offset=1040)
                    ECWNDM,       = struct.unpack_from("8s", output_buffer, offset=1048)
                   
                    # Setup array to select STATUS bits to verify
                    #statuserr = array.array('I',[26])
                    #errchk = status_check(statuserr,int(SYSINFO,16))
                    #if (errchk):
                    #    status_err_cnt += 1
                    #    error_string=("At time: %s, %s SYSINFO error, bit %d xxx failed.\n" % (localtime,self.sensor,statuserr[0]))
                    #    filesde.write(error_string)
                    #    window['STATUS'].update('WARNING STATUS ERROR DETECTED {:d} TIMES'.format(status_err_cnt))
                    
                    # Convert displayed parameters to FLOAT from Ascii Hex String format
                    heading = ahex2float(HeadingS)
                    pitch = ahex2float(PitchS)
                    roll = ahex2float(RollS)
                    veln = ahex2float(VelnS)
                    vele = ahex2float(VeleS)
                    velv = ahex2float(VelvS)
                    lat = ahex2float(LatS)
                    long = ahex2float(LongS)
                    osd = ahex2float(OsdS)
                    gpslat = ahex2float(GPSlatS)
                    gpslon = ahex2float(GPSlonS)
                    gpsfom = ahex2float(GPSfomS)
                    dbk = ahex2float(DbkS)
                    
                    # Generate Checksum
                    #checksum_calc = int(SOM,16) + int(SYSINFO,16) + int(SYSPM,16) + int(SENSORID,16) + int(DEPTHS,16) + int(DEPTHVELS,16) + int(DEPTHACCS,16) + int(DEPTHVALID,16) + int(RES1,16) + int(RES2,16) + int(RES3,16)
                    # If calculated checksum rolls over max value, truncate
                    #checksum_calc = checksum_calc % 0x100000000
                    
                    #checksum,         = struct.unpack_from("8s", output_buffer, offset=88)
                    
                    # Compare Calculated Checksum with Read Checksum
                    #if (checksum_calc != int(checksum,16)):
                    #    chksum_err_cnt += 1
                        #print('Checksum error detected')
                    #    error_string=("At time: %s, checksum error, expected %08x, detected %08x.\n" % (localtime,checksum_clac,int(checksum,16)))
                    #    filesde.write(error_string)
                    #    window['CHECKSUM'].update('WARNING CHECKSUM ERROR DETECTED {:d} TIMES'.format(chksum_err_cnt))

                    # Setup formatted csv string to write to output file, convert bytes to string with decode
                    csv_string = ("%2.5f,%2.5f,%2.5f,%2.5f,%2.5f,%2.5f,%2.5f,%2.5f,%2.5f,%s\n" % (heading,pitch,roll,veln,vele,velv,lat,long,osd,NIWN1.decode(),deltatim))
                    if (self.csv_out == True):
                        filesd.write(csv_string)
                    # Display live capture results to output window
                    window['PARM1'].update('{:3.5f}'.format(velv))
                    window['PARM2'].update('{:3.5f}'.format(depth))
                    window['PARM3'].update('{:3.5f}'.format(heading))
                    window['DLTTIM'].update('{:3.5f}'.format(deltatim))
                    window['MAXTIM'].update('{:3.5f}'.format(max_pkt_tim))
                    window['PKTCNT'].update(packet_counter)
                    window['ELPTIM'].update('{:3.5f}'.format(elapsed_tim))
                    window.refresh()

            except AttributeError as e:
                print(e)
        # Close error and CSV files
        filesde.close()
        if (self.csv_out == True):
            filesd.close()
        # End pysharklive FUNCTION

'''
=====================================================================================================
# Setup Live Run Time Output Window
=====================================================================================================
'''
def setup_outputwindow(parm1,parm2,parm3,sensor):

    # Setup GUI Run Time window columns
    data_output_column = [
        [
	    sg.Checkbox(sensor, default = True, text_color="green"),
        ],
        [
            sg.Text("{:<16}".format(parm1)),
            sg.InputText(key="PARM1",size=(10,1),disabled=False,do_not_clear=True,justification='r')
        ],
        [
            sg.Text("{:<16}".format(parm2)),
            sg.InputText(key="PARM2",size=(10,1),disabled=False,do_not_clear=True,justification='r')
        ],
        [
            sg.Text("{:<16}".format(parm3)),
            sg.InputText(key="PARM3",size=(10,1),disabled=False,do_not_clear=True,justification='r')
        ],
        [
            sg.Text("\n\nPYSHARK LIVE CAPTURE STATUS:",  text_color="green"),
        ],
        [
            sg.Text("ALL TIME DISPLAYED IN SECONDS\n",  text_color="green"),
        ],
        [
            sg.Text("{:<18}".format("DELTA TIME")),
            sg.InputText(key="DLLTIM",size=(10,1),disabled=False,do_not_clear=True,justification='r')
        ],
        [
            sg.Text("{:<18}".format("MAX TIME INTERVAL")),
            sg.InputText(key="MAXTIM",size=(10,1),disabled=False,do_not_clear=True,justification='r')
        ],
        [
            sg.Text("{:<18}".format("ELAPSED TIME")),
            sg.InputText(key="ELPTIM",size=(10,1),disabled=False,do_not_clear=True,justification='r')
        ],
        [
            sg.Text('',key='WARNING', justification='left', text_color="red"),
        ],
        [
            sg.Text('',key='CHECKSUM', justification='left', text_color="red"),
        ],
        [
            sg.Text('',key='STATUS', justification='left', text_color="red"),
        ],
        [
            sg.Text('',key='-time-', justification='left'),
        ],
        [
            sg.Button("EXIT"),
        ],
    ]

    # Display Ohio SSBN Submarine Image
    image_viewer_column = [
        [sg.Image("OhioSub.png")],	# Python 3
        #[sg.Image("OhioSub.gif")],	# Python 2
    ]
    
    # ----- Pyshark Live Capture GUI layout -----
    layout = [
        [
            sg.Column(image_viewer_column),
            sg.VSeperator(),
            sg.Column(data_output_column),
        ]    
    ]

    # Return Created Window
    return sg.Window("Pyshark Live Capture Status",layout,finalize=True)
    # End setup_outputwindow() function

'''
=====================================================================================================
# Upon operator selection of Checkbox for Setup GUI, update color, disable other checkboxes
=====================================================================================================
'''
def update_checkboxes(selection):
    if (selection == 'dhsyl1'):
        window["dhsyl1cb"].update(value=True) # Check on
        window["dhsyl1cb"].update(text_color="green")
    else:
        window["dhsyl1cb"].update(value=False) # Check off
        window["dhsyl1cb"].update(text_color="red")
    if (selection == 'dhsyl2'):
        window["dhsyl2cb"].update(value=True)
        window["dhsyl2cb"].update(text_color="green")
    else:
        window["dhsyl2cb"].update(value=False)
        window["dhsyl2cb"].update(text_color="red")
    if (selection == 'ddd1'):
        window["ddd1cb"].update(value=True)
        window["ddd1cb"].update(text_color="green")
    else:
        window["ddd1cb"].update(value=False)
        window["ddd1cb"].update(text_color="red")
    if (selection == 'ddd2'):
        window["ddd2cb"].update(value=True)
        window["ddd2cb"].update(text_color="green")
    else:
        window["ddd2cb"].update(value=False)
        window["ddd2cb"].update(text_color="red")
    if (selection == 'gyro'):
        window["gyrocb"].update(value=True)
        window["gyrocb"].update(text_color="green")
    else:
        window["gyrocb"].update(value=False)
        window["gyrocb"].update(text_color="red")
    if (selection == 'sdm'):
        window["sdmcb"].update(value=True)
        window["sdmcb"].update(text_color="green")
    else:
        window["sdmcb"].update(value=False)
        window["sdmcb"].update(text_color="red")
    if (selection == 'ndm'):
        window["ndmcb"].update(value=True)
        window["ndmcb"].update(text_color="green")
    else:
        window["ndmcb"].update(value=False)
        window["ndmcb"].update(text_color="red")
    # End update_checkboxes() function

'''
=====================================================================================================
# START MAIN FUNCTION
=====================================================================================================
'''
logging.basicConfig()

# Pyshark GUI Operator Entry, window layout of three columns
data_entry_column = [
    [
        sg.Text("Select ONE TACNAV Input to Capture", size=(40,1))
    ],
    [
	sg.Checkbox("DHSYL1 : Digital High Speed Log 1", default = True, text_color="green", enable_events=True, key='dhsyl1cb'),
    ],
    [
	sg.Checkbox("DHSYL2 : Digital High Speed Log 2", default = False, text_color="red", enable_events=True, key='dhsyl2cb'),
    ],
    [
	sg.Checkbox("DDD1 : Digital Depth Detector 1", default = False, text_color="red", enable_events=True, key='ddd1cb'),
    ],
    [
	sg.Checkbox("DDD2 : Digital Depth Detector 2", default = False, text_color="red", enable_events=True, key='ddd2cb'),
    ],
    [
	sg.Checkbox("GYRO : Gyroscope Navigation", default = False, text_color="red", enable_events=True, key='gyrocb'),
    ],
    [
    ],
    [
        sg.Text("{:<32}".format("CAPTURE TIME (Minutes)                          ")),
        sg.InputText(key="CAPTIME",size=(10,1),disabled=False,do_not_clear=True,justification='r')
    ],
    [
        sg.Text("{:<32}".format("MAX NUMBER OF PACKETS DROPPED")),
        sg.InputText(key="INTTIME",size=(10,1),disabled=False,do_not_clear=True,justification='r')
    ],
    [
        sg.Text("{:<32}".format("ETHERNET PORT                                      ")),
        sg.InputText(key="ETHPORT",size=(10,1),disabled=False,do_not_clear=True,justification='r')
    ],
    [
        sg.Button("START"),
    ],
    [
        sg.Button("EXIT"),
    ],
]
    
data_entry_column2 = [
    [
        sg.Text("OR Select NEIS Output to Capture", size=(40,1))
    ],
    [
	sg.Checkbox("SDM : Ship Data Message", default = False, text_color="red", enable_events=True, key='sdmcb'),
    ],
    [
	sg.Checkbox("NDM : Navigation Data Message", default = False, text_color="red", enable_events=True, key='ndmcb'),
    ],
]

# Display Ohio SSBN Submarine Image
image_viewer_column = [
    [sg.Image("OhioSub.png")],	# Python 3
    #[sg.Image("OhioSub.gif")],	# Python 2
    [
	sg.Checkbox("OUTPUT FILE FORMAT PCAP", default = False, enable_events=True, key='pcapcb'),
    ],
    [
        sg.Text("Default Format CSV"),
    ],
    [
	sg.Checkbox("SELECT TO DISABLE CSV", default = False, enable_events=True, key='csvcb'),
    ],
    [
        sg.Text("Error file and GUI only"),
    ],
]
    
# ----- Operator Data Entry layout -----
layout = [
    [
        sg.Column(image_viewer_column),
        sg.VSeperator(),
        sg.Column(data_entry_column),
        sg.VSeperator(),
        sg.Column(data_entry_column2),
    ]    
]

#=====================================================================================================
# Create Pyshark Live Capture Setup window with layout programmed above
#=====================================================================================================
# Python 3
#window = sg.Window("Pyshark Live Capture Setup", layout, size=(1500,400), enable_close_attempted_event=True, finalize=True)
# Python 2
window = sg.Window("Pyshark Live Capture Setup", layout, size=(1350,500), finalize=True)

# Set initial default values for input fields
window['CAPTIME'].update("10.0")	# Initial Capture time, 10 minutes
window['INTTIME'].update("16")		# Initial Interval timeout, 16 packet times missed (62.5 msec), 1 second
window['ETHPORT'].update("eth0")	# Ethernet Port

# Pcap output file turned off by default
pcap_out = False
# Csv output file generate turned on by default
csv_out = True
# Capture mode enabled by default
capture_mode = True

#=====================================================================================================
# PyShark Capture Setup Event loop
#=====================================================================================================
while True:
    # Update every 10 seconds
    event, values = window.read(timeout=10000)
    # End program if user closes window or presses the EXIT button
    if event == "EXIT" or event == sg.WIN_CLOSE_ATTEMPTED_EVENT:
        capture_mode = False
        break
    # Checkbox Handling Events
    if event == "dhsyl1cb":
        update_checkboxes("dhsyl1")
    if event == "dhsyl2cb":
        update_checkboxes("dhsyl2")
    if event == "ddd1cb":
        update_checkboxes("ddd1")
    if event == "ddd2cb":
        update_checkboxes("ddd2")
    if event == "gyrocb":
        update_checkboxes("gyro")
    if event == "sdmcb":
        update_checkboxes("sdm")
    if event == "ndmcb":
        update_checkboxes("ndm")
    if event == "csvcb":
        csv_out = False
    if event == "pcapcb":
        pcap_out = False
    if event == "START":
        now = datetime.now()
        d1 = now.strftime("%m/%d/%Y")
        d2 = now.strftime("%H:%M:%S")
        timeout = values['CAPTIME']
        int_time = values['INTTIME']
        interface = values['ETHPORT']
        # Convert pkt_int_time to seconds from packets
        pkt_int_time = float(int_time) * 0.0625		# 16 Hz packet rate, 62.5 milliseconds
        interface = values['ETHPORT']
        if values['dhsyl1cb'] is True:
            sensor = "dhsyl1"
        if values['dhsyl2cb'] is True:
            sensor = "dhsyl2"
        if values['ddd1cb'] is True:
            sensor = "ddd1"
        if values['ddd2cb'] is True:
            sensor = "ddd2"
        if values['gyrocb'] is True:
            sensor = "gyro"
        if values['sdmcb'] is True:
            sensor = "sdm"
        if values['ndmcb'] is True:
            sensor = "ndm"
        break

window.close()

# Start capture on selected interface, output file name, packet count, sensor, timeout
if (capture_mode == True):
    pysl = pysharklive(interface,"pyshark.pcap",sensor,float(timeout),pkt_int_time,pcap_out,csv_out)
