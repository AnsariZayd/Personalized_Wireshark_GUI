import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageDraw, ImageFont, ImageTk
import pyshark
import threading
from queue import Queue

class PacketCaptureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Capture App")

        # Get screen width and height
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Calculate width and height for upper left quarter
        upper_left_width = screen_width // 2
        upper_left_height = screen_height // 2

        # Set geometry for the main window
        self.root.geometry(f"{upper_left_width * 2}x{upper_left_height}+0+0")

        # Create frame to contain packet display window
        self.packet_frame = ttk.Frame(self.root)
        self.packet_frame.place(x=0, y=40, width=upper_left_width, height=upper_left_height-65)

        # Create packet display window
        self.packet_tree = ttk.Treeview(self.packet_frame, columns=(
            'Packet Number', 'Time', 'Source IP', 'Destination IP', 'Protocol', 'Length'), show='headings')
        self.packet_tree.heading('Packet Number', text='Packet Number', anchor='center')
        self.packet_tree.heading('Time', text='Time', anchor='center')
        self.packet_tree.heading('Source IP', text='Source IP', anchor='center')
        self.packet_tree.heading('Destination IP', text='Destination IP', anchor='center')
        self.packet_tree.heading('Protocol', text='Protocol', anchor='center')
        self.packet_tree.heading('Length', text='Length', anchor='center')
        self.packet_tree.column('Packet Number', width=80, anchor='center')
        self.packet_tree.column('Time', width=150, anchor='center')
        self.packet_tree.column('Source IP', width=120, anchor='center')
        self.packet_tree.column('Destination IP', width=120, anchor='center')
        self.packet_tree.column('Protocol', width=100, anchor='center')
        self.packet_tree.column('Length', width=80, anchor='center')
        self.packet_tree.pack(fill=tk.BOTH, expand=True)

        # Bind selection event to show packet details
        self.packet_tree.bind("<<TreeviewSelect>>", self.show_packet_details)

        # Create packet detail pane
        self.detail_frame = ttk.Frame(self.root)
        self.detail_frame.place(x=upper_left_width, y=40, width=upper_left_width, height=upper_left_height - 140)

        self.detail_text = tk.Text(self.detail_frame)
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        # Create packet byte detail pane
        self.packet_bytes_frame = ttk.Frame(self.root)
        self.packet_bytes_frame.place(x=upper_left_width, y=upper_left_height - 90, width=upper_left_width,
                                      height=70)

        self.packet_bytes_text = tk.Text(self.packet_bytes_frame)
        self.packet_bytes_text.pack(fill=tk.BOTH, expand=True)

        # Create header frame to contain IP and TCP/UDP header visual representations
        self.ip_header_frame = ttk.Frame(self.root)
        self.ip_header_frame.place(x=0, y=370, width=650,
                                height=350)

        self.tcp_header_frame = ttk.Frame(self.root)
        self.tcp_header_frame.place(x=650, y=370, width=710,
                                height=350)

        # Create canvas for IP header visual representation
        self.ip_header_canvas = tk.Canvas(self.ip_header_frame, bg="white")
        self.ip_header_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        # Add heading above the IP header canvas
        self.ip_header_heading = ttk.Label(self.ip_header_frame, text="IP Header Format")
        self.ip_header_heading.place(x=250, y=0)

        # Create canvas for TCP header visual representation
        self.tcp_header_canvas = tk.Canvas(self.tcp_header_frame, bg="white")
        self.tcp_header_canvas.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        self.tcp_header_heading = ttk.Label(self.tcp_header_frame, text="TCP / UDP Header Format")
        self.tcp_header_heading.place(x=300, y=0)

        # Create start and stop capture buttons
        self.capture_button = tk.Button(self.root, text="Start Capture", command=self.start_capture)
        self.capture_button.place(x=10, y=5)

        self.stop_button = tk.Button(self.root, text="Stop Capture", command=self.stop_capture)
        self.stop_button.place(x=120, y=5)
        self.stop_button["state"] = "disabled"

        # # Create filter bar
        # self.filter_label = ttk.Label(self.root, text="Filter:")
        # self.filter_label.place(x=10, y=upper_left_height - 90)
        #
        # self.filter_entry = ttk.Entry(self.root)
        # self.filter_entry.place(x=60, y=upper_left_height - 90)
        #
        # self.apply_filter_button = tk.Button(self.root, text="Apply Filter", command=self.apply_filter)
        # self.apply_filter_button.place(x=220, y=upper_left_height - 90)
        #
        # # Create status bar
        # self.status_label = ttk.Label(self.root, text="Status:")
        # self.status_label.place(x=10, y=upper_left_height - 60)
        #
        # self.status_text = ttk.Label(self.root, text="Ready")
        # self.status_text.place(x=60, y=upper_left_height - 60)

        # Initialize variables for capture process and thread
        self.capture_process = Queue()
        self.capture_thread = None
        self.is_capture_running = False
        self.live_capture = None  # To hold the LiveCapture instance

    def start_capture(self):
        self.capture_button["state"] = "disabled"
        self.stop_button["state"] = "normal"
        self.packet_tree.delete(*self.packet_tree.get_children())

        self.is_capture_running = True
        self.live_capture = pyshark.LiveCapture(interface="Wi-Fi", display_filter="ip",
                                                decode_as={"udp.port==12345": "rtp"},
                                                use_json=True, include_raw=True)
        self.capture_thread = threading.Thread(target=self.update_packet_list)
        self.capture_thread.start()

    def stop_capture(self):
        self.is_capture_running = False
        if self.capture_thread is not None:
            self.capture_thread.join()
        self.capture_button["state"] = "normal"
        self.stop_button["state"] = "disabled"

    def show_packet_details(self, event):
        # Clear previous packet details
        self.detail_text.delete("1.0", tk.END)
        self.packet_bytes_text.delete("1.0", tk.END)

        # Get selected packet
        selected_item = self.packet_tree.selection()
        if selected_item:
            packet_index = int(self.packet_tree.index(selected_item[0]))
            packet = self.capture_process.queue[packet_index]

            if packet:
                # Display packet details
                packet_number = packet[0]
                packet_time = packet[1]
                packet_src = packet[2]
                packet_dst = packet[3]
                packet_proto = packet[4]
                packet_length = packet[5]

                # Insert headings with bold font
                self.detail_text.insert(tk.END, f"Packet Number: ", 'bold')
                self.detail_text.insert(tk.END, f"{packet_number}\n")
                self.detail_text.insert(tk.END, f"Time: ", 'bold')
                self.detail_text.insert(tk.END, f"{packet_time}\n")
                self.detail_text.insert(tk.END, f"Source IP: ", 'bold')
                self.detail_text.insert(tk.END, f"{packet_src}\n")
                self.detail_text.insert(tk.END, f"Destination IP: ", 'bold')
                self.detail_text.insert(tk.END, f"{packet_dst}\n")
                self.detail_text.insert(tk.END, f"Protocol: ", 'bold')
                self.detail_text.insert(tk.END, f"{packet_proto}\n")
                self.detail_text.insert(tk.END, f"Length: ", 'bold')
                self.detail_text.insert(tk.END, f"{packet_length}\n")

                # Display additional details for TCP packets
                if packet_proto == "TCP":
                    self.detail_text.insert(tk.END, "\nTCP Packet format has these fields:\n", 'bold')
                    self.detail_text.insert(tk.END, "A TCP segment consists of data bytes to be sent and a header that is added to the data by TCP as shown: \n")
                    self.detail_text.insert(tk.END, "The header of a TCP segment can range from 20-60 bytes. 40 bytes are for options. If there are no options, a header is 20 bytes else it can be of upmost 60 bytes. Header fields: \n")
                    self.detail_text.insert(tk.END,
                                            "Source Port Address (16 bits):", 'bold')
                    self.detail_text.insert(tk.END, "A 16-bit field that holds the port address of the application that is sending the data segment.\n")
                    self.detail_text.insert(tk.END,
                                            "Destination Port Address (16 bits):", 'bold')
                    self.detail_text.insert(tk.END, "A 16-bit field that holds the port address of the application in the host that is receiving the data segment.\n")

                    self.detail_text.insert(tk.END,
                                            "Sequence Number (32 bits):", 'bold')
                    self.detail_text.insert(tk.END, " A 32-bit field that holds the sequence number, i.e, the byte number of the first byte that is sent in that particular segment. It is used to reassemble the message at the receiving end of the segments that are received out of order. \n")
                    self.detail_text.insert(tk.END,
                                            "Acknowledgement Number (32 bits):", 'bold')
                    self.detail_text.insert(tk.END, "A 32-bit field that holds the acknowledgement number, i.e, the byte number that the receiver expects to receive next. It is an acknowledgement for the previous bytes being received successfully. \n")
                    self.detail_text.insert(tk.END,
                                            "Header Length (HLEN):", 'bold')
                    self.detail_text.insert(tk.END, "This is a 4-bit field that indicates the length of the TCP header by a number of 4-byte words in the header, i.e if the header is 20 bytes(min length of TCP header), then this field will hold 5 (because 5 x 4 = 20) and the maximum length: 60 bytes, then it’ll hold the value 15(because 15 x 4 = 60). Hence, the value of this field is always between 5 and 15. \n")
                    self.detail_text.insert(tk.END,
                                            "Control flags:", 'bold')
                    self.detail_text.insert(tk.END, "These are 6 1-bit control bits that control connection establishment, connection termination, connection abortion, flow control, mode of transfer etc. Their function is: "
                                                    "\n URG: Urgent pointer is valid"
                                                    "\n ACK: Acknowledgement number is valid( used in case of cumulative acknowledgement)"
                                                    "\n PSH: Request for push"
                                                    "\n RST: Reset the connection"
                                                    "\n SYN: Synchronize sequence numbers"
                                                    "\n FIN: Terminate the connection\n")
                    self.detail_text.insert(tk.END, "Window size:", 'bold')
                    self.detail_text.insert(tk.END, "This field tells the window size of the sending TCP in bytes. \n")
                    self.detail_text.insert(tk.END, "Checksum", 'bold')
                    self.detail_text.insert(tk.END, "This field holds the checksum for error control. It is mandatory in TCP as opposed to UDP. \n")
                    self.detail_text.insert(tk.END, "Urgent pointer", 'bold')
                    self.detail_text.insert(tk.END, "This field (valid only if the URG control flag is set) is used to point to data that is urgently required that needs to reach the receiving process at the earliest. The value of this field is added to the sequence number to get the byte number of the last urgent byte. \n")


                elif packet_proto == "UDP":
                    self.detail_text.insert(tk.END, "\nAdditional details of UDP: \n", 'bold')
                    self.detail_text.insert(tk.END,
                                            "\nUDP header is an 8-byte fixed and simple header, while for TCP it may vary from 20 bytes to 60 bytes.\n")
                    self.detail_text.insert(tk.END,
                                            "The first 8 Bytes contain all necessary header information and the remaining part consists of data.\n")
                    self.detail_text.insert(tk.END,
                                            "UDP port number fields are each 16 bits long, therefore the range for port numbers is defined from 0 to 65535; port number 0 is reserved.\n")
                    self.detail_text.insert(tk.END,
                                            "Port numbers help to distinguish different user requests or processes.\n")
                    self.detail_text.insert(tk.END,
                                            "Source Port:", 'bold')
                    self.detail_text.insert(tk.END, " Source Port is a 2 Byte long field used to identify the port number of the source.\n")
                    self.detail_text.insert(tk.END,
                                            "Destination Port:", 'bold')
                    self.detail_text.insert(tk.END, " It is a 2 Byte long field, used to identify the port of the destined packet.\n")
                    self.detail_text.insert(tk.END,
                                            "Length:", 'bold')
                    self.detail_text.insert(tk.END, " Length is the length of UDP including the header and the data. It is a 16-bits field.\n")
                    self.detail_text.insert(tk.END,
                                            "Checksum:",'bold')
                    self.detail_text.insert(tk.END, " Checksum is 2 Bytes long field. It is the 16-bit one’s complement of the one’s complement sum of the UDP header, the pseudo-header of information from the IP header, and the data, padded with zero octets at the end (if necessary) to make a multiple of two octets.\n")


                # Configure tag for bold text
                self.detail_text.tag_configure('bold', font=('TkDefaultFont', 10, 'bold'))

                # Display packet bytes for the selected packet
                self.display_packet_bytes(packet)

                # Display header frame format and visual representation
                if packet_proto == "TCP":
                    self.display_header_frame("IP", packet, canvas=self.ip_header_canvas)
                    self.display_header_frame("TCP", packet, canvas=self.tcp_header_canvas)
                elif packet_proto == "UDP":
                    self.display_header_frame("IP", packet, canvas=self.ip_header_canvas)
                    self.display_header_frame("UDP", packet, canvas=self.tcp_header_canvas)

    def display_packet_bytes(self, packet):
        # Display packet bytes in packet bytes detail pane
        if packet:
            self.packet_bytes_text.insert(tk.END, "Packet Bytes (in binary):\n")
            raw_packet = packet[6]  # Get the raw packet data
            total_bits = len(raw_packet) * 8  # Calculate the total number of bits
            bits_per_line = 4 * 17  # 8 packets of 4 bits each
            bits_per_byte = 8  # Number of bits in a byte
            bytes_per_line = bits_per_line // bits_per_byte  # Calculate the number of bytes per line

            # Calculate the start and end bit index for the IP header
            ip_header_start_bit = 113
            ip_header_end_bit = 272

            # Calculate the start and end byte indices for displaying
            start_byte_index = 0
            end_byte_index = len(raw_packet)

            for i in range(start_byte_index, end_byte_index, bytes_per_line):
                byte_group = raw_packet[i:i + bytes_per_line]
                for j, byte in enumerate(byte_group):
                    binary_byte = format(byte, '08b')  # Convert byte to binary string
                    # Insert a space after every 4 bits
                    binary_byte_spaced = ' '.join(binary_byte[k:k + 4] for k in range(0, len(binary_byte), 4))
                    start_bit = i * 8 + j * 8
                    end_bit = start_bit + 8
                    # Check if the current byte is within the IP header range
                    if ip_header_start_bit <= start_bit < ip_header_end_bit or \
                            ip_header_start_bit <= end_bit < ip_header_end_bit:
                        # Apply highlighting to the bits within the IP header range
                        self.packet_bytes_text.insert(tk.END, f"{binary_byte_spaced} ", 'highlight')
                    else:
                        self.packet_bytes_text.insert(tk.END, f"{binary_byte_spaced} ")
                self.packet_bytes_text.insert(tk.END, "\n")

            # Configure tag for highlighted text
            self.packet_bytes_text.tag_configure('highlight', background='yellow', foreground='black')

    def display_header_frame(self, protocol, packet, canvas):
        # Clear previous content in the canvas
        canvas.delete("all")

        # Get the dimensions of the canvas
        canvas_width = canvas.winfo_width()
        canvas_height = canvas.winfo_height()

        if protocol == "IP":
            # Load IP header image
            ip_header_image = Image.open("ip_header_format_revised.png")
            draw = ImageDraw.Draw(ip_header_image)
            font = ImageFont.load_default()

            # Get the specified bits from the packet
            raw_packet = packet[6]
            ip_header_bits = ''.join(format(byte, '08b') for byte in raw_packet[14:34]) # 49 to 68

            # Define coordinates for each set of bits
            bit_positions = [
                (37, 45),  # Position for the first set of bits
                (92, 45),  # Position for the second set of bits
                (152, 45),
                (184, 45),
                (300, 45),
                (330, 45),
                (360, 45),
                (390, 45),
                (37, 100),
                (64, 100),
                (170, 100),
                (197, 100),
                (242, 100),
                (270, 100),
                (298, 100),
                (326, 100),
                (25, 130),
                (102, 130),
                (135, 130),
                (205, 130),
                (245, 130),
                (275, 130),
                (400, 130),
                (432, 130),
                (65, 155),
                (95, 155),
                (125, 155),
                (155, 155),
                (295, 155),
                (325, 155),
                (355, 155),
                (385, 155),
                (65, 180),
                (95, 180),
                (125, 180),
                (155, 180),
                (295, 180),
                (325, 180),
                (355, 180),
                (385, 180),

            ]

            # Print the bits at different positions
            for i, pos in enumerate(bit_positions):
                bits_set = ip_header_bits[i * 4: (i + 1) * 4]  # Extract 4 bits for each set
                draw.text(pos, bits_set, fill=(0, 0, 0), font=font)

            # Convert the image for tkinter display
            ip_header_image_tk = ImageTk.PhotoImage(ip_header_image)
            canvas.create_image(0, 0, anchor=tk.NW, image=ip_header_image_tk)
            canvas.image = ip_header_image_tk  # Keep reference to prevent garbage collection


        elif protocol == "TCP":

            # Load TCP header image

            tcp_header_image = Image.open("tcp_header_revised.png")

            draw = ImageDraw.Draw(tcp_header_image)

            font = ImageFont.load_default()

            # Get the specified bits from the packet

            raw_packet = packet[6]

            tcp_header_bits = ''.join(format(byte, '08b') for byte in raw_packet[33:])

            # Define coordinates for each set of bits

            bit_positions = [

                (98, 75),  # Position for the first set of bits
                (128, 75),  # Position for the second set of bits
                (158, 75),
                (188, 75),
                (300, 75),
                (330, 75),
                (360, 75),
                (390, 75),
                (65, 135),
                (95, 135),
                (125, 135),
                (155, 135),
                (340, 135),
                (370, 135),
                (400, 135),
                (430, 135),
                (65, 163),
                (90, 163),
                (115, 163),
                (140, 163),
                (370, 163),
                (395, 163),
                (420, 163),
                (445, 163),
                (25, 200),
                (125, 204),
                (170, 204),
                (200, 204),
                (280, 204),
                (310, 204),
                (410, 204),
                (440, 204),
                (65, 240),
                (95, 240),
                (190, 240),
                (220, 240),
                (280, 240),
                (310, 240),
                (410, 240),
                (440, 240),



                # Add more positions as needed

            ]

            # Print the bits at different positions

            for i, pos in enumerate(bit_positions):
                bits_set = tcp_header_bits[i * 4: (i + 1) * 4]  # Extract 4 bits for each set

                draw.text(pos, bits_set, fill=(0, 0, 0), font=font)

            # Convert the image for tkinter display

            tcp_header_image_tk = ImageTk.PhotoImage(tcp_header_image)

            canvas.create_image(0, 0, anchor=tk.NW, image=tcp_header_image_tk)

            canvas.image = tcp_header_image_tk  # Keep reference to prevent garbage collection


        elif protocol == "UDP":

            # Load UDP header image

            udp_header_image = Image.open("udp_header_format.png")

            draw = ImageDraw.Draw(udp_header_image)

            font = ImageFont.load_default()

            # Get the specified bits from the packet

            raw_packet = packet[6]

            udp_header_bits = ''.join(format(byte, '08b') for byte in raw_packet[34:42])

            # Define coordinates for each set of bits

            bit_positions = [

                (105, 110),  # Position for the first set of bits
                (135, 110),  # Position for the second set of bits
                (163, 110),
                (193, 110),
                (295, 110),
                (325, 110),
                (355, 110),
                (385, 110),
                (115, 215),  # Position for the first set of bits
                (145, 215),  # Position for the second set of bits
                (173, 215),
                (203, 215),
                (295, 215),
                (325, 215),
                (355, 215),
                (385, 215),

                # Add more positions as needed

            ]

            # Print the bits at different positions

            for i, pos in enumerate(bit_positions):
                bits_set = udp_header_bits[i * 4: (i + 1) * 4]  # Extract 4 bits for each set

                draw.text(pos, bits_set, fill=(0, 0, 0), font=font)

            # Convert the image for tkinter display

            udp_header_image_tk = ImageTk.PhotoImage(udp_header_image)

            canvas.create_image(0, 0, anchor=tk.NW, image=udp_header_image_tk)

            canvas.image = udp_header_image_tk  # Keep reference to prevent garbage collection

    def update_packet_list(self):
        for packet in self.live_capture.sniff_continuously():
            if not self.is_capture_running:
                break

            packet_number = packet.number
            packet_time = packet.sniff_time.strftime("%Y-%m-%d %H:%M:%S")
            packet_src = packet.ip.src
            packet_dst = packet.ip.dst
            packet_proto = packet.transport_layer
            packet_length = packet.length
            raw_packet = packet.get_raw_packet()

            # Add packet details to the queue
            self.capture_process.put((packet_number, packet_time, packet_src, packet_dst, packet_proto, packet_length, raw_packet))

            # Update packet tree display
            self.root.after(100, self.update_packet_tree)

    def update_packet_tree(self):
        # Clear existing items in the packet tree
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)

        # Insert packets into the packet tree
        for packet in list(self.capture_process.queue):
            self.packet_tree.insert('', 'end', values=(
                packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]))

    def apply_filter(self):
        filter_text = self.filter_entry.get()
        self.capture_process.queue.clear()  # Clear existing packets in the queue
        if filter_text:
            self.live_capture.set_display_filter(filter_text)
            self.status_text.config(text=f"Filter applied: {filter_text}")
        else:
            self.status_text.config(text="No filter applied")

# Instantiate and run the application
root = tk.Tk()
app = PacketCaptureApp(root)
root.mainloop()