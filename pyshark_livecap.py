'''
Created on Dec 20, 2022

@author: Jeff Stearns
'''

import array
import pyshark
import time
import logging
import struct
#import PySimpleGUI as sg	#Tkinter base GUI, Python 3
import trollius			#Python 2

from ctypes import *
from datetime import datetime

#Setup GUI theme and font
#sg.theme('DarkTanBlue')	#Py3
#wfont=("liberation mono",16)	#Mono space font family
#sg.set_options(font=wfont)

'''
=====================================================================================================
# Function to Check Status Word for Errors : Array of bit locations, statuserr, and integer status
# word, statusint, passed in. Selected bit locations compared to '0', no error.
=====================================================================================================
'''
def status_check(statuserr,statusint):
    errchk = 0
    bitlen = len(statuserr)
    binstat = format(statusint,#034b)
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
        err_fname = 'Packet_Error_{0}{1:02d}{2:02d}_{3:02d}{4:02d}.csv'.format{start.tm_year,start.tm_mon,start.tm_mday,start.tm_hour,start.tm_min)
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
        #if (self.sensor == "dhsyl1" or self.sensor == "dhsyl2"):
        #    window = setup_outputwindow("EMWTRSPD","BLNDWSPD","DISTANCE",self.sensor)
        #if (self.sensor == "ddd1" or self.sensor == "ddd2"):
        #    window = setup_outputwindow("DEPTH","DEPTHVEL","DEPTHACC",self.sensor)
        #if (self.sensor == "gyro"):
        #    window = setup_outputwindow("HEADING","ROLL","PITCH",self.sensor)
        #if (self.sensor == "ndm"):
        #    window = setup_outputwindow("VELOCITY","DEPTH","HEADING",self.sensor)
        #if (self.sensor == "sdm"):
        #    window = setup_outputwindow("EMLOG1","DDD1","GYRO",self.sensor)

        #Setup csv file for sensor data capture if enabled
        if (self.csv_out == True):
            fname = '{0}_{1}{2:02d}{3:02d}_{4:02d}{5:02d}.csv'.format{self.sensor,start.tm_year,start.tm_mon,start.tm_mday,start.tm_hour,start.tm_min)
            filesd = open(fname,'w')        
            # Store capture start time at beginning of CSV file
            csv_timestamp = ("%s\n"%time.asctime(time.localtime(time.time())))

        for packet in capture.sniff_continuously(packet_count=self.pkt_count):
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
                    error_string=("At time: %s, Time Interval of %f exceeded, Time Interval %f detected.\n", % (localtime,self.pkt_int_time,deltatim))
                    filesde.write(error_string)
                    pkt_interr_cnt += 1
                    #window['WARNING'.update('WARNING PACKET TIMEOUT DETECTED {:d} TIMES'.format(pkt_interr_cnt))

                # output packet info
                print("%s %s:%s <-> %s:%s (%s)" % (localtime, src_addr, src_port, dst_addr, dst_port, protocol))
                print("%d" % pllen)
                #print("%s" % payload)

                # DHSYL1,2 : 27 words, 4 bytes each, 108 bytes total
                plbytes = payload.split(':')
                if ((self.sensor == "dhsyl1" or self.sensor == "dhsyl2") and drop_packet == False):
                    # Write out fields with data, all other fields are always 0
                    if (packet_counter == 1 and self.csv_out == True):
                        filesd.write("SYSTATS1,SYSTATS2,EMWTRSPD,BLNDWSPD,DISTANCE,CHECKSUM,DELTATIM\n)
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
                    errchk = 0
                    errchk = status_check(statuserr,int(SYSTATUS1,16))
                    if (errchk):
                        status_err_cnt += 1
                        error_string=("At time: %s, %s SYSTATUS1 error, bit %d EM_SENSOR_SPEED_INVALID failed.\n" % (localtime,self.sensor,statuserr[0]))
                        filesde.write(error_string)
                        #window['STATUS'].update('WARNING STATUS ERROR DETECTED {:d} TIMES'.format(status_err_cnt))
                    
                    # Convert displayed parameters to FLOAT from Ascii Hex String format
                    EMWaterSpeed = ahex2float(EMWaterSpeeds)
                    BlendWaterSpeed = ahex2float(BlendWaterSpeeds)
                    distance = ahex2float(distances)
                    
                    # Generated Checksum
                    checksum_calc = int(SYSTATUS1,16) + int(SYSTATUS2,16) + int(DPLSTATUS,16) + int(BTMFVEL,16) + int(BTMAVEL,16) + int(BTMVVEL,16) + int(BTMSPD,16) + int(BTMRNG1,16) + int(BTMRNG2,16) + int(BTMRNG3,16) + int(BTMRNG4,16) + int(BTMDST,16) + int(WTRFVEL,16) + int(WTRAVEL,16) + int(WTRVVEL,16) + int(DPLWTRSPD,16) + int(DPLSENSC,16) + int(EMWaterSpeeds,16) + int(BlendWaterSpeeds,16) + int(distances,16) + int(WTEMP,16) + int(DOPP_ROLL,16) + int(DOPP_PITCH,16) + int(DOPP_HDG,16) + int(UPDRATE,16) + int(RSV,16)
                    # If calculated checksum rolls over max value, truncate
                    while (checksum_calc > 0xFFFFFFFF):
                        checksum_calc = checksum_calc % 0x100000000
                    
                    checksum,         = struct.unpack_from("8s", output_buffer, offset=208)
                    
                    # Compare Calculated Checksum with Read Checksum
                    if (checksum_calc != int(checksum,16)):
                        checksum_err_cnt += 1
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
                    window['PARM2'].update('{:3.5f}'.format(EMWaterSpeed))
                    window['PARM3'].update('{:3.5f}'.format(EMWaterSpeed))
                    window['DLTTIM'].update('{:3.5f}'.format(EMWaterSpeed))
                    window['MAXTIM'].update('{:3.5f}'.format(EMWaterSpeed))
                    window['PKTCNT'].update('{:3.5f}'.format(EMWaterSpeed))
                    window['ELPTIM'].update('{:3.5f}'.format(EMWaterSpeed))
                    window.refresh()

            except AttributeError as e:
                print(e)
            # End pysharklive FUNCTION

'''
=====================================================================================================
START MAIN FUNCTION
=====================================================================================================
'''
logging.basicConfig()

# Hard code parameters for now
interface = "xxx"
sensor = "dhsyl1"
timeout = "1"
pkt_int_time = 28 * 0.0625
pcap_out = False
csv_out = False

# Start capture on selected interface, output file name, packet count, sensor, timeout
pysl = pysharklive(interface,"pyshark.pcap",sensor,float(timeout),pkt_int_time,pcap_out,csv_out)
