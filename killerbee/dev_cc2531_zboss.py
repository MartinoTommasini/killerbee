# coding=utf-8
import struct
import usb.core
import usb.util
import time
from datetime import datetime
from kbutils import makeFCS
from array import array

from kbutils import KBCapabilities


def _to_array(data):
    return array('B', [data])


class CC2531:
    USB_START_SNIFFING = 0xAA
    USB_STOP_SNIFFING = 0xBB
    USB_SEND_PACKET = 0xCC

    USB_EP4_OUT = 0x04
    USB_EP4_IN = 0x84
    USB_EP2_IN = 0x82

    def __init__(self, dev, bus):

        self._channel = None
        self.dev = dev
        self.is_sniffing = False
        self.capabilities = KBCapabilities()
        self.__set_capabilities()

        """ Resolves usbError: resource busy """
        self.dev.reset()
        if self.dev.is_kernel_driver_active(0):
            self.dev.detach_kernel_driver(0)
        self.dev.set_configuration()

        # get name from USB descriptor
        self.name = usb.util.get_string(self.dev, self.dev.iProduct)

        # Get wMaxPacketSize from the data endpoint (expected 64)
        for cfg in self.dev:
            for intf in cfg:
                for ep in intf:
                    if ep.bEndpointAddress == CC2531.USB_EP4_OUT:
                        self._maxPacketSize = ep.wMaxPacketSize

    def _do_set_channel(self):
        self.dev.write(CC2531.USB_EP4_OUT, array('B', [self._channel]), 100)

    def set_channel(self, channel, page=0):
        """
        Sets the radio interface to the specifid channel (limited to 2.4 GHz channels 11-26)
        @type channel: Integer
        @param channel: Sets the channel, optional
        @type page: Integer
        @param page: Sets the subghz page, not supported on this device
        @rtype: None
        """
        # self.capabilities.require(KBCapabilities.SETCHAN)

        if channel >= 11 or channel <= 26:
            self._channel = channel
            self._do_set_channel()
        else:
            raise Exception('Invalid channel')
        if page:
            raise Exception('SubGHz not supported')

    def __set_capabilities(self):
        """
            <Sets the capability information appropriate for CC2531.
            @rtype: None
            @return: None
        """
        self.capabilities.setcapab(KBCapabilities.FREQ_2400, True)
        self.capabilities.setcapab(KBCapabilities.SNIFF, True)
        self.capabilities.setcapab(KBCapabilities.SETCHAN, True)
        self.capabilities.setcapab(KBCapabilities.INJECT, True)

    # KillerBee expects the driver to implement this function
    def sniffer_on(self, channel=None, page=0):
        """
        Turns the sniffer on such that pnext() will start returning observed data.
        Will set the command mode to Air Capture if it is not already set.
        @type channel: Integer
        @param channel: Sets the channel, optional
        @type page: Integer
        @param page: Sets the subghz page, not supported on this device
        @rtype: None
        """
        self.capabilities.require(KBCapabilities.SNIFF)

        if channel is not None:
            self.set_channel(channel, page)

        # Start capture
        self.dev.write(CC2531.USB_EP4_OUT, _to_array(CC2531.USB_START_SNIFFING))
        self.is_sniffing = True

    # KillerBee expects the driver to implement this function
    def sniffer_off(self):
        """
        Turns the sniffer off, freeing the hardware for other functions.  It is
        not necessary to call this function before closing the interface with
        close().
        @rtype: None
        """
        if self.is_sniffing is True:
            # TODO Here, and in other places, add error handling for ctrl_transfer failure
            self.dev.write(CC2531.USB_EP4_OUT, _to_array(CC2531.USB_STOP_SNIFFING))
            self.is_sniffing = False

    def close(self):
        if self.is_sniffing:
            self.sniffer_off()
        pass

    def check_capability(self, capab):
        return self.capabilities.check(capab)

    def get_capabilities(self):
        return self.capabilities.getlist()

    def get_dev_info(self):
        """
        Returns device information in a list identifying the device.
        @rtype: List
        @return: List of 3 strings identifying device.
        """
        # TODO Determine if there is a way to get a unique ID from the device
        return [self.name, "CC2531", ""]

    # KillerBee expects the driver to implement this function
    def pnext(self, timeout=100):
        """
        Returns a dictionary containing packet data, else None.
        @type timeout: Integer
        @param timeout: Timeout to wait for packet reception in usec
        @rtype: List
        @return: Returns None is timeout expires and no packet received.  When a packet is received, a dictionary is returned with the keys bytes (string of packet bytes), validcrc (boolean if a vaid CRC), rssi (unscaled RSSI), and location (may be set to None). For backwards compatibility, keys for 0,1,2 are provided such that it can be treated as if a list is returned, in the form [ String: packet contents | Bool: Valid CRC | Int: Unscaled RSSI ]
        """
        if self.is_sniffing is False:
            self.sniffer_on()  # start sniffing

        ret = None
        framedata = []

        while True:
            pdata = None
            try:
                pdata = self.dev.read(CC2531.USB_EP4_IN, self._maxPacketSize, timeout=timeout)
            except usb.core.USBError as e:
                if e.errno != 110:  # Operation timed out
                    print("Error args: {}".format(e.args))
                    raise e
                    # TODO error handling enhancements for USB 1.0
                else:
                    return None

            # Accumulate in 'framedata' until we have an entire frame
            for byteval in pdata:
                framedata.append(struct.pack("B", byteval))

            if len(pdata) < 64:
                print ('An entire packet arrived')
                # TODO delete passage of len field from firmware
                """ PACKET STRUCTURE:
                    -2 preamble : 0xad , 0x13
                    -1 len of Zigbee mac packet    # to remove 
                    -1 len of Zigbee mac packet. Includes:
                        -mac header
                        -mac payload
                        -2 bytes mac footer (RSII+CRC_OK or FCS )
                    -variable zigbee packet (header + payload)                   
                    -2 mac footer (RSII + CRC_OK) 
                """

                if len(pdata) < 2:
                    print "ERROR: Very short frame"
                    return None

                # check if preamble is valid
                if framedata[0] != '\xad' or framedata[1] != '\x13':
                    print('Not a valid packet')
                    return None

                # skip framedata[2] : len field

                mac_packet = framedata[4:]
                mac_packet_len = ord(framedata[3])
                if len(mac_packet) != mac_packet_len:
                    print "ERROR: Bad frame length: expected {0}, got {1}".format(mac_packet_len, len(mac_packet))
                    return None

                # See TI Smart RF User Guide for usage of 'CC24XX' format FCS fields
                # in last two bytes of framedata. Note that we remove these before return of the frame.

                # RSSI is signed value, offset by 73 (see CC2530 data sheet for offset)
                rssi = struct.unpack("b", framedata[-2])[0] - 73

                fcsx = ord(framedata[-1])
                # validcrc is the bit 7 in fcsx
                validcrc = (fcsx & 0x80) == 0x80
                # correlation value is bits 0-6 in fcsx
                correlation = fcsx & 0x7f

                ret = {1: validcrc, 2: rssi,
                       'validcrc': validcrc, 'rssi': rssi, 'lqi': correlation,
                       'dbm': rssi, 'datetime': datetime.utcnow()}

                # Convert the mac packet to a string for the return value, and replace the TI FCS with a real FCS
                # if the radio told us that the FCS had passed validation.

                if validcrc:
                    ret[0] = ''.join(mac_packet[:-2]) + makeFCS(mac_packet[:-2])
                else:
                    ret[0] = ''.join(mac_packet)
                ret['bytes'] = ret[0]
            
                return ret

    # KillerBee expects the driver to implement this function
    def inject(self, packet, channel=None, count=1, delay=0, page=0):
        '''
        Injects the specified packet contents.
        @type packet: String
        @param packet: Packet contents to transmit, without FCS.
        @type channel: Integer
        @param channel: Sets the channel, optional
        @type page: Integer
        @param page: Sets the subghz page, not supported on this device
        @type count: Integer
        @param count: Transmits a specified number of frames, def=1
        @type delay: Float
        @param delay: Delay\ between each frame, def=0
        @rtype: None
        '''
        self.capabilities.require(KBCapabilities.INJECT)

        # set minimum delay to 0.0007 s
        # needed in transition from transmission to reception (e.g. zbstumbler)
        if delay < 0.0007:
            delay = 0.0007

        if len(packet) < 1:
            raise Exception('Empty packet')
        if len(packet) > 125:  # 127 - 2 to accommodate FCS
            raise Exception('Packet too long')

        if channel != None:
            self.set_channel(channel, page)
        if page:
            raise Exception('SubGHz not supported')

        for pnum in range(0, count):
            # tell the usb that a packet is going to arrive
            self.dev.write(CC2531.USB_EP4_OUT, _to_array(CC2531.USB_SEND_PACKET), 100)

            # 64 byte packets sent at a time
            if len(packet) <= 64:
                # print(packet)
                self.dev.write(CC2531.USB_EP4_OUT, packet, 100)
                # toDO: manage 64 byte packets. Not supported from firmware.
            else:
                # print(packet[:64])
                # print(packet[64:])
                self.dev.write(CC2531.USB_EP4_OUT, packet[:64], 100)
                self.dev.write(CC2531.USB_EP4_OUT, packet[64:], 100)
            time.sleep(delay)

