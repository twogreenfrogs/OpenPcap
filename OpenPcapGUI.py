'''
History
v1.0.0 - Initial release(09/28/2018)

'''
import time
import ttk
import threading
import sys
import os
import re
import psutil
import logging
import datetime
import config
from subprocess import call, Popen, PIPE, STDOUT
from threading import Timer
from string import Template

try:
    # for python 2.x
    import Tkinter as tk
    import tkMessageBox
    from Queue import Queue, Empty

except ImportError:
    # for python 3.x
    import tkinter as tk
    import messagebox
    from queue import Queue, Empty

#global variables
VERSION = '1.0.0'
# logging control flag. If True, print to stdout, or log file
IS_UNDER_TEST = False
LOG_TO_CONSOLE = False

def get_logger(name=None, level=logging.DEBUG, to_console=LOG_TO_CONSOLE, log_file='debug.log'):
    logger = logging.getLogger(name or __name__)

    # if it is under test or there is debug.log file then start logging
    if IS_UNDER_TEST or os.path.isfile('debug.log'):
        logger.setLevel(level)       
        formatter = logging.Formatter('%(asctime)s[%(lineno)s] %(message)s')
        logger.disabled = False

        if to_console:
            s_handler = logging.StreamHandler(sys.stdout)
            s_handler.setFormatter(formatter)
            logger.addHandler(s_handler)
        else:
            f_handler = logging.FileHandler(log_file)
            f_handler.setFormatter(formatter)
            logger.addHandler(f_handler)
        
    else:
        logger.disabled = True

    return logger

def pyinstaller_resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath('.'), relative_path)


class OpenPCap(object):
    """
    OpenPcap class
    """
    CHANNELS_24G = ['CH 1 [2.412 GHz]',
                    'CH 2 [2.417 GHz]',
                    'CH 3 [2.422 GHz]',	
                    'CH 4 [2.427 GHZ]',
                    'CH 5 [2.432 GHz]',	
                    'CH 6 [2.437 GHz]',
                    'CH 7 [2.442 GHz]',
                    'CH 8 [2.447 GHz]',
                    'CH 9 [2.452 GHz]',
                    'CH 10 [2.457 GHz]',
                    'CH 11 [2.462 GHz]',
                    'CH 12 [2.467 GHz]',
                    'CH 13 [2.472 GHz]',
                    'CH 14 [2.484 GHz]',
                    ]
    CHANNELS_5G = ['CH 36 [5.180 GHz]',
                   'CH 38 [5.190 GHz]',
                   'CH 40 [5.200 GHz]',
                   'CH 42 [5.210 GHz]',
                   'CH 44 [5.220 GHz]',
                   'CH 46 [5.230 GHz]',
                   'CH 48 [5.240 GHz]',
                   'CH 149 [5.745 GHz]',
                   'CH 151 [5.755 GHz]',
                   'CH 153 [5.765 GHz]',
                   'CH 155 [5.775 GHz]',
                   'CH 157 [5.785 GHz]',
                   'CH 159 [5.795 GHz]',
                   'CH 161 [5.805 GHz]',
                   'CH 165 [5.825 GHz]',
                   ]
    
    def __init__(self, ipaddr=config.ipaddr, username=config.username, password=config.password, logger=None):
        self.ipaddr = ipaddr
        self.username = username
        self.password = password
        self.logger = logger
        
    def execute_cmd(self, cmd):
        self.logger.debug('got cmd: {}'.format(cmd))
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)

        stdout, stderr = p.communicate()

        # if stderr is not empty, then return err
        if stderr.strip():
            self.logger.debug('execute_cmd failed. stdout: {}, stderr: {}'.format(stdout, stderr))
            return False, stdout, stderr
        return True, stdout, stderr

        
    def is_pingable(self, ipaddr=None, cnt=1, wait=2000):
        ping_cmd = Template('ping -n $cnt -w $wait $ipaddr').substitute(cnt=cnt, wait=wait, ipaddr=ipaddr or self.ipaddr)

        #to supress cmd window, use Popen instead of os.system
        success, stdout, stedrr = self.execute_cmd(ping_cmd)
        
        if 'Destination host unreachable' in stdout or '(100% loss)' in stdout:
            self.logger.debug('ping failed')
            return False
        else:
            return True

    def is_connected(self):
        if not self.is_pingable():
            self.logger.debug('Device not connected')
            return False

        # to do: need to check ssh connectivity
        return True

    
class StatusCheckThread(threading.Thread):
    """
    Thread to check Device connectivity and wireshark status in background
    """
    def __init__(self, opcap, status_queue, logger, *args, **kwargs):
        threading.Thread.__init__(self, *args, **kwargs)
        self.opcap = opcap
        self.status_queue = status_queue
        self.logger = logger
        self.stop_request = threading.Event()

    def run(self):
        # remember previous status and send message only when status changes
        prev_conn_status = False
        prev_wireshark_status = False
        
        while not self.stop_request.isSet():
            if self.opcap.is_connected():
                curr_conn_status = True
            else:
                curr_conn_status = False
                
            if curr_conn_status != prev_conn_status:
                prev_conn_status = curr_conn_status
                self.logger.debug('Connection status changed: {}'.format(curr_conn_status))
                self.status_queue.put(('IS_DEVICE_CONNECTED', curr_conn_status))

            # check if wireshark process is running
            for p in psutil.process_iter():
                try:
                    if 'wireshark' in p.name().lower():
                        curr_wireshark_status = True
                        break
                except psutil.NoSuchProcess:
                    pass
            else:
                curr_wireshark_status = False

            if curr_wireshark_status != prev_wireshark_status:
                prev_wireshark_status = curr_wireshark_status
                self.logger.debug('Wireshark running status changed: {}'.format(curr_wireshark_status))
                self.status_queue.put(('IS_WIRESHARK_RUNNING', curr_wireshark_status))
                
            time.sleep(1)
            
    def join(self, timeout=None):
        self.stop_request.set()
        self.logger.debug('StatusCheckThread stop_request set')
        threading.Thread.join(self, timeout)
        #super(StatusCheckThread, self).join(timeout)


class ExecCmdThread(threading.Thread):
    """
    Thread to execute command on OpenPcap Device and return result
    """
    def __init__(self, opcap, cmd_queue, res_queue, logger, *args, **kwargs):
        threading.Thread.__init__(self, *args, **kwargs)
        self.opcap = opcap
        self.cmd_queue = cmd_queue
        self.res_queue = res_queue
        self.logger = logger
        self.stop_request = threading.Event()
        
    def run(self):
        while not self.stop_request.isSet():
            if not self.cmd_queue.empty():
                cmd, mapping_cmd = self.cmd_queue.get()
                self.logger.debug('cmd: {}, mapping_cmd: {}'.format(cmd, mapping_cmd))
                success, stdout, stderr = self.opcap.execute_cmd(mapping_cmd)
                self.logger.debug('exec result: {}, {}, {}'.format(success, stdout, stderr))
                self.res_queue.put((cmd, (success, stdout, stderr)))
            time.sleep(1)

    def join(self, timeout=None):
        self.stop_request.set()
        self.logger.debug('ExecCmdThread stop_request set')
        threading.Thread.join(self, timeout)     

        
class OpenGUI(tk.Tk):
    """
    Class to create Open-Pcap control panel
    Get feedback from StatusCheckThread about connection and wireshark running status and update GUI status.
    Send cmd to and receive result from ExeCmdThread and update GUI status accordingly.
    Only when device is ready, it allows to execute commands.
    """
    
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)

        # logging
        self.logger = get_logger()
        
        # for pyinstaller to include everything in one executable
        try:
            #self.iconbitmap(default='resources\logo.ico')
            self.logo = pyinstaller_resource_path('resources\logo.ico')            
            self.plink = pyinstaller_resource_path('resources\plink.exe')
            self.say_yes = pyinstaller_resource_path('resources\say.yes')
        except Exception as e:
            self.logger.exception('cannot find resource files')
            try:
                #python 2.7
                tkMessageBox.showerror('Error', 'Cannot find resource files')
            except ImportError:
                #python 3.x
                messagebox.showerror('Error', 'Cannot find resource files')
            return

        self.tk_setPalette(background='ghost white')
        self.title('Open-Pcap Control Panel v{}'.format(VERSION))
        self.resizable(width=False, height=False)
        self.option_add('*Font', 'Courier 10')
        self.iconbitmap(default=self.logo)
        
        self._create_menu()
        self._create_body()
        self.opcap = OpenPCap(logger=self.logger)
        
        self.SINGLE_BAND = OpenPCap.CHANNELS_24G
        self.DUAL_BAND = OpenPCap.CHANNELS_24G + OpenPCap.CHANNELS_5G

        # flags, based on which gui status is updated
        self.IS_DEVICE_CONNECTED = False
        self.IS_WIFI_INFO_AVAILABLE = False
        self.IS_FREQUENCY_SET = False
        self.IS_SITE_SURVEY_RUNNING = False
        self.IS_WIRESHARK_RUNNING = False
        self.SHUTDOWN_IN_PROGRESS = False
        self.IS_WIRESHARK_INSTALLED = False
        self.IS_DUAL_BAND = False
        
        # device is ready only when pingable and wifi interface is checked and frequency set is done.
        self.IS_DEVICE_READY = self.IS_DEVICE_CONNECTED and self.IS_WIFI_INFO_AVAILABLE and self.IS_FREQUENCY_SET  
        
        # commands for gui program to execute            
        self.WIFI_INFO = (self.plink + ' -ssh -pw ' + config.password + ' ' + config.username + '@' + config.ipaddr + " wifi_info.sh  < " + self.say_yes)
        self.MONITOR_MODE = Template(self.plink + ' -ssh -pw ' + config.password + ' ' + config.username + '@' + config.ipaddr +" monitor_mode.sh mon0 $channel")
        self.SITE_SURVEY = Template(self.plink + ' -ssh -pw ' + config.password + ' ' + config.username + '@' + config.ipaddr + " site_survey.sh mon0 $timeout")
        self.START_WIRESHARK = Template(self.plink + ' -ssh -pw ' + config.password + ' ' + config.username + '@' + config.ipaddr + ' "tcpdump -i mon0 -U -w - 2> /dev/null"' 
                                        '| ("C:\Program Files\Wireshark\Wireshark.exe" $filter_option $filter_expression "-k" "-i" "-")')
        self.STOP_WIRESHARK = 'taskkill /F /IM wireshark.exe'
        self.STOP_PLINK = 'taskkill /F /IM plink.exe'
        self.STOP_DEVICE = (self.plink + ' -ssh -pw ' + config.password + ' ' + config.username + '@' + config.ipaddr + "  shutdown.sh")
        
        # map commands for ease of exchanging messages with Thread
        self.CMD_MAPPING ={'WIFI_INFO': self.WIFI_INFO,
                           'SITE_SURVEY': self.SITE_SURVEY,
                           'MONITOR_MODE': self.MONITOR_MODE,
                           'START_WIRESHARK': self.START_WIRESHARK,
                           'STOP_WIRESHARK': self.STOP_WIRESHARK,
                           'STOP_PLINK': self.STOP_PLINK,
                           'STOP_DEVICE': self.STOP_DEVICE,
                            }
    
        # 3 queues to communicate with Thread
        self.queue_conn_status = Queue()
        self.queue_cmd_request = Queue()
        self.queue_cmd_response = Queue()

        # thread to monitor device connectivity and wireshark running status and update main thread
        self.status_check_thread = StatusCheckThread(self.opcap, self.queue_conn_status, logger=self.logger)
        self.status_check_thread.start()

        # thread to execute cmd and return result to main thread
        self.exec_cmd_thread = ExecCmdThread(self.opcap, self.queue_cmd_request, self.queue_cmd_response, logger=self.logger)
        self.exec_cmd_thread.start()
        
        # self._update_gui_status: check queue messages from Threads and update GUI display
        self.after(100, self._update_gui_status)

        # check if wireshark is installed
        if not os.path.isfile('C:\Program Files\Wireshark\Wireshark.exe'):
            self.IS_WIRESHARK_INSTALLED = False
            self.logger.error('Cannot find Wireshark program.')
            try:
                #python 2.7
                tkMessageBox.showerror('Error', 'Cannot find Wireshark Program\nPlease install Wireshark first and restart program')
            except ImportError:
                #python 3.x
                messagebox.showerror('Error', 'Cannot find Wireshark Program\nPlease install Wireshark first and restart program')
            self._quit()
        else:
            self.IS_WIRESHARK_INSTALLED = True
        
    def _create_menu(self):
        pass

    def _create_body(self):
        SINGLE_BAND = OpenPCap.CHANNELS_24G
        DUAL_BAND = OpenPCap.CHANNELS_24G + OpenPCap.CHANNELS_5G
        # device status frame -------------------------------
        self.device_status = tk.LabelFrame(self, text='Device Status', relief=tk.GROOVE, bd=1)
        self.device_status.grid(row=0, column=0, padx=10, pady=5, sticky='NSEW')

        # device status  frame widgets
        self.lbl_conn_status = tk.Label(self.device_status, text='Connection Status:', padx=3, pady=1)
        self.lbl_wifi_interface = tk.Label(self.device_status, text='WiFi Interface:', padx=3, pady=1)
        self.lbl_conn_status_val = tk.Label(self.device_status, text='Connecting...', padx=3, pady=1, anchor='w')
        self.lbl_wifi_interface_val = tk.Label(self.device_status, text=' ', padx=3, pady=1, anchor='w', width=20)
        self.lbl_conn_status.grid(row=0, column=0, sticky='NWS' )
        self.lbl_wifi_interface.grid(row=1, column=0, sticky='NWS')
        self.lbl_conn_status_val.grid(row=0, column=1, sticky='NWS')
        self.lbl_wifi_interface_val.grid(row=1, column=1, sticky='NWS')

        #packet sniff frame ----------------------------------
        self.packet_sniff = tk.LabelFrame(self, text='Packet Sniff', relief=tk.GROOVE, bd=1)
        self.packet_sniff.grid(row=1, column=0, padx=10, pady=5, sticky='NSEW')
        self.packet_sniff.grid_columnconfigure(0, weight=1)
        self.packet_sniff.grid_columnconfigure(1, weight=2)
        #packet sniff frame variables
        self.var_channel_option = tk.StringVar(self.packet_sniff)
        self.var_channel_option.set('CH 1 [2.412 GHz]')

        # packet sniff frame widgets
        self.lbl_site_survey = tk.Label(self.packet_sniff, text='Site Survey:', padx=3, pady=1)
        self.lbl_set_channel = tk.Label(self.packet_sniff, text='Set Channel:', padx=3, pady=1)
        self.lbl_set_filter = tk.Label(self.packet_sniff, text='Set Filter:', padx=3, pady=1)
        self.lbl_start_sniff = tk.Label(self.packet_sniff, text='WireShark:', padx=3, pady=1)
        self.btn_site_survey = tk.Button(self.packet_sniff, text='Start',
                                         command=lambda: self._send_cmd_to_thread('SITE_SURVEY', 10 if self.IS_DUAL_BAND else 5),
                                         bd=1, padx=3, pady=1)
        self.options_set_channel = tk.OptionMenu(self.packet_sniff, self.var_channel_option, *SINGLE_BAND)
        # call back when channel changes
        self.var_channel_option.trace('w', lambda *args: self._send_cmd_to_thread('MONITOR_MODE'))

        self.options_set_channel['highlightthickness'] = 0
        self.options_set_channel['bd'] = 1
        self.options_set_channel['padx'] = 3
        self.options_set_channel.config(width=12)

        self.ent_set_filter = tk.Entry(self.packet_sniff, fg='grey', bg='snow', bd=1)
        self.ent_set_filter.delete(0, tk.END)
        self.ent_set_filter.insert(0, 'Optional(xx:xx:xx:xx:xx:xx)')
        self.ent_set_filter.bind('<Button-1>', lambda event: self.ent_set_filter.delete(0, tk.END))
        self.btn_start_sniff = tk.Button(self.packet_sniff, text='Start',
                                         command=lambda: self._send_cmd_to_thread('START_WIRESHARK' if not self.IS_WIRESHARK_RUNNING
                                                                                  else 'STOP_WIRESHARK'),
                                        width=12, bd=1, padx=3, pady=1)
        self.lbl_site_survey.grid(row=0, column=0, sticky='NWS')
        self.lbl_set_channel.grid(row=1, column=0, sticky='NWS')
        self.lbl_set_filter.grid(row=2, column=0, sticky='NWS')
        self.lbl_start_sniff.grid(row=3, column=0, sticky='NWS')

        self.btn_site_survey.grid(row=0, column=1, sticky='NEWS')
        self.options_set_channel.grid(row=1, column=1, sticky='NEWS')
        self.ent_set_filter.grid(row=2, column=1, sticky='NEWS', padx=1, pady=1)
        self.btn_start_sniff.grid(row=3, column=1, sticky='NEWS')

        # Device control frame -----------------------------------
        self.device_control = tk.LabelFrame(self, text='Device Control', relief=tk.GROOVE, bd=1)
        self.device_control.grid(row=2, column=0, padx=10, pady=5, sticky='NSEW')
        self.device_control.grid_columnconfigure(0, weight=1)
        self.device_control.grid_columnconfigure(1, weight=2)
        
        # device status  frame widgets
        self.lbl_device_shutdown = tk.Label(self.device_control, text='Open-Pcap:', padx=3, pady=1)
        self.btn_device_shutdown = tk.Button(self.device_control, text='Shutdown Gracefully',
                                             command=lambda: self._send_cmd_to_thread('STOP_DEVICE'),
                                             bd=1, padx=3, pady=1, bg='SteelBlue1', width=16)
        self.lbl_device_shutdown.grid(row=0, column=0, sticky='NWS' )
        self.btn_device_shutdown.grid(row=0, column=1, sticky='NEWS' )


        # bottom frame --------------------------------------------
        self.bottom_menu = tk.Frame(self)
        self.bottom_menu.grid(row=3, column=0, sticky='NEWS')

        # bottom frame widgets
        self.lbl_status = tk.Label(self.bottom_menu, text='Status: Not Ready', fg='red', width=20, anchor=tk.W, justify=tk.LEFT)
        self.lbl_status.grid(row=0, column=0, sticky='NEWS', padx=10, pady=5)
        self.btn_exit = tk.Button(self.bottom_menu, text='Exit', command=self._quit, width=10)
        self.btn_exit.grid(row=0, column=1, sticky='NEWS', padx=10, pady=5)
        self.bottom_menu.grid_columnconfigure(0, weight=2)
        self.bottom_menu.grid_columnconfigure(1, weight=1)
        
    def _show_site_survey_result(self, result):
        """
        Show WiFi Site Survery result in separate Window
        """
        win_site_survey = tk.Toplevel(self)
        win_site_survey.resizable(width=False, height=False)
        win_site_survey.title('Open-Pcap')
        
        # position child window right side of control panel
        # why y-pos is slightly down below main window??
        x = self.winfo_rootx()
        y = self.winfo_rooty()
        
        h = self.winfo_height()
        w = self.winfo_width()
        geom = '+{}+{}'.format(x+w, y)
        win_site_survey.geometry(geom)

        result_frame = tk.LabelFrame(win_site_survey, text='WiFi Site Survey Result', relief=tk.GROOVE, bd=1)
        result_frame.grid(row=0, column=0, padx=5, pady=0, sticky='NSEW')

        scrollbar = tk.Scrollbar(result_frame)
        scrollbar.pack(side = tk.RIGHT, fill = tk.Y)
        text_box = tk.Text(result_frame, yscrollcommand = scrollbar.set, width=55, height=25, borderwidth=0)
        #text_box.delete(1.0, tk.END)
        text_box.insert(tk.END, result)
        text_box.config(state=tk.DISABLED)
        
        text_box.pack(side = tk.LEFT, fill = tk.BOTH)
        scrollbar.config(command = text_box.yview)

        bottom_frame = tk.Frame(win_site_survey)
        bottom_frame.grid(row=1, column=0, sticky='NEWS')

        btn_quit = tk.Button(bottom_frame, text='Exit', width=10, command=win_site_survey.destroy)
        btn_quit.pack(side=tk.RIGHT, padx=5, pady=5)
        
    def _send_cmd_to_thread(self, cmd=None, *args):
        self.logger.debug('received cmd: {}'.format(cmd))
        if cmd == 'MONITOR_MODE':
            if self.IS_WIRESHARK_RUNNING or self.IS_SITE_SURVEY_RUNNING:
                self.logger.debug('Wireshark is running: {}, Site Survey is running: {}'.format(self.IS_WIRESHARK_RUNNING,
                                                                                                self.IS_SITE_SURVEY_RUNNING))
                try:
                    #python 2.7
                    tkMessageBox.showerror("Error", "Other Task Running Please Wait...")
                except ImportError:
                    #python 3.x
                    messagebox.showerror("Error", "Other Task Running Please Wait...")
                return

            # Neither Wireshark nor Site Survey is running.
            #Now changing wifi interface to Monitor mode and set to target Frequency
            self.IS_FREQUENCY_SET = False
            channel = self.var_channel_option.get().split()[1]
            self.logger.debug('Chaning WiFi channel to {}'.format(channel))
            mapping_cmd = self.CMD_MAPPING[cmd].substitute(channel=channel)

        elif cmd == 'WIFI_INFO':
            self.logger.debug( self.CMD_MAPPING[cmd])
            mapping_cmd = self.CMD_MAPPING[cmd]

        else:
            # for all other commands, wait until device is ready
            self.IS_DEVICE_READY = self.IS_DEVICE_CONNECTED and self.IS_WIFI_INFO_AVAILABLE and self.IS_FREQUENCY_SET
            self.logger.debug('device status - Conn: {}, WiFi: {}, Freq: {}'.format(self.IS_DEVICE_CONNECTED,
                                                                                    self.IS_WIFI_INFO_AVAILABLE,
                                                                                    self.IS_FREQUENCY_SET))
            if not self.IS_DEVICE_READY:
                self.logger.debug('device not ready. just returning...')
                try:
                    #python 2.7
                    tkMessageBox.showerror('Error', 'Device Not Ready Yet...')
                except ImportError:
                    #python 3.x
                    messagebox.showerror('Error', 'Device Not Ready Yet...')
                return
            
            if cmd == 'START_WIRESHARK':
                if self.IS_SITE_SURVEY_RUNNING:
                    self.logger.debug('site survey is running. do not start wireshark')
                    try:
                        tkMessageBox.showerror('Error', 'Site Survey is running. Please Wait...')
                    except ImportError:
                        messagebox.showerror('Error', 'Site Survey is running. Please Wait...')
                    return

                filter_expression = self.ent_set_filter.get()
                if filter_expression and not 'xx:xx:xx:xx:xx:xx' in filter_expression:
                    # this means user entered capture filter option. 
                    if not re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', filter_expression, re.I):
                        try:
                            tkMessageBox.showerror('Error', 'Invalid capture filter')
                        except ImportError:
                            messagebox.showerror('Error', 'Invalid capture filter')
                        return
                    else:
                        filter_expression = '"wlan.addr==' + filter_expression + '"'
                        filter_option='"-f"'
                else:
                    # this means no capture filter set
                    filter_expression = ''
                    filter_option=''

                self.logger.debug('filter option: {}, filter expression: {}'.format(filter_option, filter_expression))
                    
                if not self.IS_WIRESHARK_RUNNING and self.IS_WIRESHARK_INSTALLED:
                    self.IS_WIRESHARK_RUNNING = True    
                    mapping_cmd = self.CMD_MAPPING[cmd].substitute(filter_option=filter_option, filter_expression=filter_expression)
                else:
                    #prevent double-click in short period of time which causes double wireshark launching
                    return
                    
            elif cmd == 'STOP_WIRESHARK':
                mapping_cmd = 'taskkill /IM wireshark.exe'
                from subprocess import call, Popen, PIPE, STDOUT
                p = Popen(mapping_cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
                stdout, stderr = p.communicate()
                return
                
            elif cmd == 'STOP_PLINK':
                mapping_cmd = 'taskkill /IM plink.exe /F /T'
                from subprocess import call, Popen, PIPE, STDOUT
                p = Popen(mapping_cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
                stdout, stderr = p.communicate()
                return
                
            elif cmd == 'SITE_SURVEY':
                if self.IS_WIRESHARK_RUNNING:
                    self.logger.debug('wireshark is running. do not start site survey')
                    try:
                        tkMessageBox.showerror('Error', 'Wireshark is running. Please Wait...')
                    except ImportError:
                        messagebox.showerror.showerror('Error', 'Wireshark is running. Please Wait...')
                    return
                
                if not self.IS_SITE_SURVEY_RUNNING:
                    self.IS_SITE_SURVEY_RUNNING = True
                    mapping_cmd = self.CMD_MAPPING[cmd].substitute(timeout=args[0])
                else:
                    return
            elif cmd == 'STOP_DEVICE':
                # double-confirm 
                try:
                    yes = tkMessageBox.askyesno('Exit', 'Do you really want to shutdown device?')
                except:
                    yes = messagebox.askyesno('Exit', 'Do you really want to shutdown device??')
                if not yes:
                    return
                mapping_cmd = self.CMD_MAPPING[cmd]
            else:
                mapping_cmd = self.CMD_MAPPING[cmd]

        # now send cmd to ExeCmdThread
        self.logger.debug('send cmd to ExeCmdThread: cmd:{}, mapping_cmd:{}'.format(cmd, mapping_cmd))
        self.queue_cmd_request.put((cmd, mapping_cmd))
    
    def _update_gui_status(self):
        # this gets called every 3s and update GUI display
        
        if not self.queue_conn_status.empty():
            MSG_TYPE, STATUS = self.queue_conn_status.get()
            self.logger.debug('status msg - MSG_TYPE: {}, STATUS: {}'.format(MSG_TYPE, STATUS))
            self.queue_conn_status.task_done()

            if MSG_TYPE == 'IS_DEVICE_CONNECTED':
                self.IS_DEVICE_CONNECTED = STATUS
                if self.IS_DEVICE_CONNECTED:
                    self.lbl_conn_status_val['text'] = 'Connected'
                    self.logger.debug('device connected. getting wifi info and setting initial channel')
                    self._send_cmd_to_thread('WIFI_INFO')
                    #self._send_cmd_to_thread('MONITOR_MODE')
                else:
                    self.IS_WIFI_INFO_AVAILABLE = False
                    self.IS_FREQUENCY_SET = False
                    self.lbl_conn_status_val['text'] = 'Connecting...'
                    self.lbl_wifi_interface_val['text'] = ' '
                    
            elif MSG_TYPE == 'IS_WIRESHARK_RUNNING':
                self.IS_WIRESHARK_RUNNING = STATUS
                if self.IS_WIRESHARK_RUNNING:
                    self.btn_start_sniff['text'] = 'Stop(Wireshark Running)'
                else:
                    self.btn_start_sniff['text'] = 'Start'
            else:
                pass
                
        if not self.queue_cmd_response.empty():
            # check what cmd, its response and update gui          
            CMD_TYPE, (success, stdout, stderr) = self.queue_cmd_response.get()
            self.logger.debug('CMD_TYPE: {}, success: {}, stdout: {}, stderr: {}'.format(CMD_TYPE, success, stdout, stderr))
            self.queue_cmd_response.task_done()
            
            if CMD_TYPE == 'WIFI_INFO':
                if '802.11' in stdout:
                    if '2.4G' in stdout and '5G' in stdout:
                        self.logger.debug('wifi interface: Dual band')
                        # update available channels
                        self.IS_DUAL_BAND = True
                        self.options_set_channel['menu'].delete(0, 'end')
                        self.var_channel_option.set('CH 1 [2.412 GHz]')
                        for channel in self.DUAL_BAND:
                            self.options_set_channel['menu'].add_command(label=channel,
                                                                  command=tk._setit(self.var_channel_option, channel))
                    else:
                        self.logger.debug('wifi interface: Single band')

                    # strip spaces and also 'Unable to use key file' which might come if ssh key auth fails.
                    # if ssh key auth fails, plink tries with password.
                    # ToDo: just parse out wifi info from stdout using regular expression
                    if "The server's host key" in stdout:
                        #this is first time so need to parse output
                        self.lbl_wifi_interface_val['text'] = stdout.split('(y/n)')[-1].strip()
                    else:
                        self.lbl_wifi_interface_val['text'] = stdout.split('Unable to use key file')[0].strip()
                    self.IS_WIFI_INFO_AVAILABLE = True
                    # only after device is connected and wifi info is available, config monitor mode
                    self._send_cmd_to_thread('MONITOR_MODE')
                else:
                    try:
                        #python 2.7
                        tkMessageBox.showerror('Error', 'No WiFi Device\n')
                    except ImportError:
                        #python 3.x
                        messagebox.showerror('Error', 'No WiFi Device\n')
                        
                    self.lbl_wifi_interface_val['text'] = 'No WiFi Device'
                    self.logger.debug('err in wifi info. stdout: {}'.format(stdout))
                    
            elif CMD_TYPE == 'SITE_SURVEY':
                self.IS_SITE_SURVEY_RUNNING = False
                self.logger.debug('got site survey result: {}'.format(stdout.strip('\n').split('Unable to use key file')[0]))
                self._show_site_survey_result(stdout.strip('\n').split('Unable to use key file')[0])

                # here need to re configure wifi channel as site_survey hopps different channels
                self._send_cmd_to_thread('MONITOR_MODE')
            
            elif CMD_TYPE == 'MONITOR_MODE':
                # if fail, show error message
                if not success or 'Error for wireless request' in stdout or 'Unable to open connection' in stdout:
                    self.logger.debug('Error for wireless setting request: {}'.format(stdout))
                    try:
                        #python 2.7
                        tkMessageBox.showerror('Error', 'Set Frequency Failed...\n'
                                               '(This Frequency is not supported in WiFi Device)')
                        self.var_channel_option.set('CH 1 [2.412 GHz]')
                    except ImportError:
                        #python 3.x
                        messagebox.showerror('Error', 'Set Frequency Failed...\n'
                                               '(This Frequency is not supported in WiFi Device)')
                        self.var_channel_option.set('CH 1 [2.412 GHz]')
                        
                    self.logger.debug('Frequency setting failed...')
                    self.IS_FREQUENCY_SET = False
                elif 'No such device' in stdout:
                    try:
                        #python 2.7
                        tkMessageBox.showerror('Error', 'No WiFi Device')
                    except ImportError:
                        #python 3.x
                        messagebox.showerror('Error', 'No WiFi Device')                 
                else:
                    self.IS_FREQUENCY_SET = True
            elif CMD_TYPE == 'STOP_DEVICE':
                self.SHUTDOWN_IN_PROGRESS = True
                self.btn_device_shutdown['text'] = 'Shutdown in Progress...'
                self.btn_device_shutdown['bg'] = 'orange red'
            
            else:
                # ignore START_WIRESHARK or STOP_WIRESHARK.
                # Wireshark running status is monitored by ChkStatusThread
                pass

        # other statuff to update gui from flags files.       
        self.IS_DEVICE_READY = self.IS_DEVICE_CONNECTED and self.IS_WIFI_INFO_AVAILABLE and self.IS_FREQUENCY_SET
        if not self.IS_DEVICE_READY:
            self.logger.debug('device not ready - conn: {}, wifi_info: {}, freq set: {}'.format(self.IS_DEVICE_CONNECTED,
                                                                                                self.IS_WIFI_INFO_AVAILABLE,
                                                                                                self.IS_FREQUENCY_SET))
            if not self.IS_DEVICE_CONNECTED:
                self.lbl_status['text'] = 'Status: Not Ready'
            elif not self.IS_WIFI_INFO_AVAILABLE:
                self.lbl_status['text'] = 'Status: Checking WiFi'
            elif not self.IS_FREQUENCY_SET:
                # device ready but frequency not set
                self.lbl_status['text'] = 'Status: Setting Freq'
            else:
                self.lbl_status['text'] = 'Status: Unknown Err'
            self.lbl_status.config(fg='red')
        else:
            # device ready
            self.lbl_status['text'] = 'Status: Device Ready'
            self.lbl_status.config(fg='forest green')
        
        if self.IS_SITE_SURVEY_RUNNING:
            duration = 25 if self.IS_DUAL_BAND else 5
            if 'Start' in self.btn_site_survey.cget('text'):
                self.btn_site_survey['text'] = 'In Progress({}s)...'.format(duration)
                self.start_time = datetime.datetime.now()
            else:
                remaining_time = duration - ((datetime.datetime.now() - self.start_time).seconds)
                remaining_time = 0 if remaining_time < 0 else remaining_time
                self.btn_site_survey['text'] = 'In Progress({}s)...'.format(remaining_time)
                
        if not self.IS_SITE_SURVEY_RUNNING and 'Start' not in self.btn_site_survey.cget('text'):
            self.btn_site_survey['text'] = 'Start'
            
        if not self.IS_DEVICE_CONNECTED:
            txt = self.lbl_conn_status_val.cget('text')
            txt = txt + '.' if len(txt) < 15 else 'Connecting'
            self.lbl_conn_status_val['text'] = txt

        if not self.IS_DEVICE_CONNECTED and self.SHUTDOWN_IN_PROGRESS:
            self.logger.debug('Open-Pcap shutdown successful!!!')
            self.SHUTDOWN_IN_PROGRESS = False
            self.btn_device_shutdown['text'] = 'Shutdown Gracefully'
            self.btn_device_shutdown['bg'] = 'SteelBlue1'
            try:
                #python 2.7
                tkMessageBox.showinfo('Shutdown', 'Shutdown Open-Pcap successful!!!')
            except ImportError:
                #python 3.x
                messagebox.showinfo('Shutdown', 'Shutdown Open-Pcap successful!!!')
    
        self.after(1000, self._update_gui_status)
            
    def _quit(self, event=None):
        if self.SHUTDOWN_IN_PROGRESS:
            try:
                #python 2.7
                tkMessageBox.showerror('Error', 'Device Shutdown In Progress\nPlease wait...')
            except ImportError:
                #python 3.x
                messagebox.showerror('Error', 'Device Shutdown In Progress\nPlease wait...')
            return
             
        try:
            yes = tkMessageBox.askyesno('Exit', 'Do you really want to quit?')
        except:
            yes = messagebox.askyesno('Exit', 'Do you really want to quit?')

        if yes:
            if self.IS_WIRESHARK_RUNNING:
                self.logger.debug('Wireshark stopping...')
                self._send_cmd_to_thread('STOP_WIRESHARK')
            if self.IS_SITE_SURVEY_RUNNING:
                self.logger.debug('Site survey stopping...')
                self._send_cmd_to_thread('STOP_PLINK')

            self.status_check_thread.join()
            self.exec_cmd_thread.join()
            self.destroy()

            
if __name__ == '__main__':
    gui = OpenGUI()
    gui.mainloop()

