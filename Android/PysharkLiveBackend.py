# PysharkLiveCapGUI.py

import PySimpleGUIQt as sg
import os.path
import tkinter.font
from datetime import datetime

#sg.theme('DarkTanBlue')
sg.theme('Topanga')
cfont='Times New Roman'

class GUI():
    def __init__(self, location):
        self.blink_count = 0

#getting current time and return it
def clk():
    ntime=datetime.now()
    nt=ntime.strftime('\n\n%H:%M:%S')
    return nt

# window layout of two columns
data_entry_column = [
    [
        sg.Checkbox("DHSYL1", default = True, text_color="green"),
    ],
    [
        sg.Text("EMWTRSPD"),
        sg.InputText(
            key="CAPTIME",size=(10,1),disabled=False,do_not_clear=True
        )
    ],
    [
        sg.Text("BLNDWSPD"),
        sg.InputText(
            key="PACKETS",size=(10,1),disabled=False,do_not_clear=True
        )
    ],
    [
        sg.Text("DISTANCE"),
        sg.InputText(
            key="DISTANCE",size=(10,1),disabled=False,do_not_clear=True
        )
    ],
    [
    sg.Button("STOP"),
    ],
    [
    sg.Text('',key='-time-',font=(cfont,16),justification='left')
    ],
]

# Display Ohio SSBN Submarine Image
image_viewer_column = [
    #[sg.Text(size=(40,1), key="-TOUT-")],
    [sg.Image("C:\Customer\Mikel\Python Sublime Project\Pyshark LiveCap GUI\OhioSub.png")],
]

# Setup filename in case operator does not select a file from the list for APPEND
filename = 'Subdata.csv'

# ----- Operator Data Entry layout -----
layout = [
    [
        sg.Column(image_viewer_column),
        sg.VSeperator(),
        sg.Column(data_entry_column),
    ]
]

# create window with programmed layout
window = sg.Window("Pyshark Live Capture Status",layout)

# create an event loop
while True:
    #Update every second
    event, values = window.read(timeout=1000)
    # End program if user closes window or presses the EXIT button
    if event == sg.WIN_CLOSED:
        break
    if event == "STOP":
        #Capture Entered Data Values from InputText boxes
        #filesd.write(values['DHSYL1'])
        #filesd.write(",")
        #filesd.write(values['DDD1'])
        #filesd.write(",")
        #filesd.write(values['GYRO'])
        #filesd.write(",")
        now = datetime.now()
        d1 = now.strftime("%m/%d/%Y")
        filesd.write(d1)
        filesd.write(",")
        d2 = now.strftime("%H:%M:%S")
        filesd.write(d2)
        filesd.write("\n")
        #Clear input text fields
        #window['DHSYL1'].update('')
        #window['DDD1'].update('')
        #window['GYRO'].update('')
    window['-time-'].update(clk())


window.close()
filesd.close()
