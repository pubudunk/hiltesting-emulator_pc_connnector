import serial
import traceback


#definitions
UART_TIMEOUT = 15 


#constants
STX = 0x02

PACKET_TYPE_TESTS  = 0x01
PACKET_TYPE_RESULTS = 0x02

TEST_ID_01 = 0x01
TEST_ID_02 = 0x02
TEST_ID_03 = 0x03
TEST_ID_04 = 0x04
TEST_ID_05 = 0x05

RESULT_PASS = 0x01
RESULT_FAIL = 0x02
RESULT_NA   = 0x03

HEADER_LEN = 2

#global variables
serialPort = None

def init_serial(port):
    """
    Initialize the serial port. Timeout is set to the value of UART_TIMEOUT (seconds)

    Args:
        port (str): The COM port to use for serial communication (e.g., 'COM6').

    Returns:
        serial.Serial: The initialized serial port object if successful, None otherwise.
    """


    global serialPort

    try:
        serialPort = serial.Serial(port, baudrate=115200, timeout=UART_TIMEOUT)
    except Exception as e:
        print(f'Exception: opening {port}: {e}')


def calculate_crc(data):
    """
    Calculate the CRC for a given data packet.

    Args:
        data (bytes): The data packet for which to calculate the CRC.

    Returns:
        int: The calculated CRC value.
    """


    crc = 0
    for byte in data:
        crc ^= byte
    
    return crc

def build_command_packet(packet_type, test_cases):
    """
    Build a packet to send over UART using the updated protocol.

    Args:
        packet_type (int): The type of the packet (0x01 for Tests)
        test_cases (list): A list of test cases, where each test case is a dictionary
                           with keys 'id', 'len', and 'val'.

    Returns:
        bytes: The constructed packet.
    """


    packet = bytearray()

    packet.append(STX)  #STX

    length = 2 # For now use the lenght as packet_type and num_tlvs (which is fixed)
    packet.append(length)       # packet lenght
    packet.append(packet_type)  # packet type

    num_tlvs = 0    #For now until total tests are processed
    packet.append(num_tlvs)  # num of tlvs

    for test in test_cases:
        packet.append(test['id']) # test id
        length += 1

        if(test['len'] > 0):
            #TODO: implement variable length tests
            pass
        else:
            packet.append(0)    # len, data is always zero
            length += 1

        num_tlvs += 1

    packet[1] = length + 1 # additional byte for CRC
    packet[3] = num_tlvs 

    crc = calculate_crc(packet)
    packet.append(crc)

    print('Created command packet:', ' '.join(f'{byte:02X}' for byte in packet))

    return packet


def send_tests(test_cases):
    """
    Send test cases to the emulator

    Args:
        test_cases (list): List of test cases to be sent. Each test case is a dictionary
                            with keys 'id', 'len', 'data' (relating to TLV format) and 'name'

    Returns:
        Test results response if sucess, None otherwise
    """


    global serialPort

    if serialPort is None:
        raise Exception("Serial port not initialized")
    
    command_packet = build_command_packet(PACKET_TYPE_TESTS, test_cases)

    try:

        #header = bytes([0x02, 0x12]) #TODO mock code remove later
        #reply_data = bytearray([0x02, 0x05, 0x01, 0x01, 0x01, 0x02, 0x01, 0x02, 0x03, 0x01, 0x03, 0x04, 0x01, 0x02, 0x05, 0x01, 0x01]) #TODO mock code remove later
        #reply_data.append(calculate_crc(header+reply_data))

        bytes_written = serialPort.write(command_packet)
        if(bytes_written != len(command_packet)):
            print("Error: Not all bytes were written to the serial port. command_packet_len: {len(command_packet)} bytes_written:{bytes_written}")
            return None
        
        # Wait for header (STX + Length + Packet Type)
        header = serialPort.read(HEADER_LEN)
        if (len(header) < HEADER_LEN) or (header[0] != STX):
            print('Error: Invalid or incomplete header received')
            return None

        length = header[1]
        # Read the remainder of the packet
        reply_data = serialPort.read(length)

        if (len(reply_data) < length):
            print(f'Error: Incomplete packet received or timedout received_len: {len(reply_data)}')
            return None

        packet_type = reply_data[0]

        if (packet_type != PACKET_TYPE_RESULTS):
            print('Error: Invalid packet type received')
            return None
        
        # Validate CRC
        reply_packet = header + reply_data[:-1]  # excluding CRC
        received_crc = reply_data[-1]
        if (received_crc != calculate_crc(reply_packet)):
            print('Error: Reply packet CRC error')
            return None
        
        print('Reply packet:', ' '.join(f'{byte:02X}' for byte in bytes(header + reply_data)))

        return bytes(header + reply_data)

    
    except serial.SerialException as e:
        print(f'Exception: Serial communication error: {e}')
        traceback.print_exc()
        return None
    

def process_reply_packet(reply_packet):
    """
    Process the reply packet from the hardware emulator.

    Args:
        reply_packet (bytes): The reply packet received from the emulator.

    Returns:
        list: A list of results, where each result is a dictionary with keys 'id', 'result', 
              'len' and 'data'
    """


    # Check for STX
    if not reply_packet or reply_packet[0] != STX:  
        print("Error: Invalid response received")
        return []
    
    # Check for Results packet type
    packet_type = reply_packet[2]
    if packet_type != PACKET_TYPE_RESULTS:  
        print("Error: Invalid packet type received")
        return []

    # Check packet length
    packet_len = reply_packet[1]
    if((packet_len + 2) != len(reply_packet)): # packet lenght does not include STX and lenght byte
        print("Error: Invalid packet length")
        return []
    
    num_tlvs = reply_packet[3]
    results = []
    index = 4

    # Parse the packet for tlvs and populate the results list of dictionaries
    for _ in range(num_tlvs):
        pass

        id = reply_packet[index]
        lenght = reply_packet[index + 1]
        result = reply_packet[index + 2]

        if(lenght > 1):
            #TODO: Reply has additional data. Handle this case later
            pass

        results.append({
            'id' : id,
            'len': lenght,
            'data': 0x00,
            'result': result
        })  
        
        index += (2 + lenght)  # tag + len + data length

    return results