import pyshark
import time
import trollius
import logging
import pygtk
import gtk

logging.basicConfig()

# define interface
networkInterface = "eth0"

class MyProgram:

    def __init__(self):

        # create a new window

        self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
        self.window.set_position( gtk.WIN_POS_CENTER );
        self.window.set_size_request(800, 640)
        self.window.set_border_width(10)
        self.window.set_title("DHSYL Reading")
        self.window.connect("delete_event", lambda w,e: gtk.main_quit())
        self.image1 = gtk.Image()
        self.image1.set_from_file("OhioSub.png")
        self.image1.xalign = 1
        self.image1.yalign = 1

        self.button1 = gtk.Button("EXIT")
        self.button2 = gtk.Button("SAVE")
        #self.button1.connect("clicked", self.exit)

        self.textview = gtk.TextView()
        self.textbuffer = self.textview.get_buffer()
        self.textbuffer.set_text("22")

        fixed = gtk.Fixed();
        fixed.put(self.button1, 0,   0)
        fixed.put(self.button2, 150, 0)
        fixed.put(self.image1,  0,   100)
        fixed.put(self.textview,300, 0)

        self.window.add(fixed);
        #hbox.pack_start(fixed)

        # Program goes here  ...

        self.window.show_all()
        return

cap = pyshark.LiveCapture(interface=networkInterface)
cap = pyshark.LiveCapture(output_file="pyshark.pcap")
#cap = pyshark.LiveCapture(output_file="pyshark.pcap", include_raw=True, use_json=True)
#cap = pyshark.LiveCapture(interface=networkInterface, bpf_filter='tcp port 80')
print("\n\nCapturing on eth0...\n")
for packet in cap.sniff_continuously(packet_count=100):
        #print(packet)
        # adjusted output
    try:
        # get timestamp
        localtime = time.asctime(time.localtime(time.time()))

        # get packet content
        # pdata  = packet.data.data         # packet data
        protocol = packet.transport_layer   # protocol type
        snifftim = packet.sniff_time        # time from previous packet
        src_addr = packet.ip.src            # source address
        src_port = packet[protocol].srcport # source port
        dst_addr = packet.ip.dst            # destination address
        dst_port = packet[protocol].dstport # destination port

        # output packet info
        # print ("%s %s IP %s:%s <-> %s:%s (%s)" % (localtime, snifftim, src_addr, src_port, dst_addr, dst_port, protoc$        print ("%s IP %s:%s <-> %s:%s (%s)" % (localtime, src_addr, src_port, dst_addr, dst_port, protocol))
    except AttributeError as e:
        # ignore packets other than TCP, UDP and IPv4
        pass
    print (" ")
    #MyProgram()
cap.clear()
cap.close()
