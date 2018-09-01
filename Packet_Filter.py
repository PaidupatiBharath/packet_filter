import pyshark

class Packet_Filter():

    def filters(self, filter_name):
        self.disp_filter = filter_name
        return self.disp_filter

    def read(self, pcap_file, disp_filter=None):
        if disp_filter:
            capture = pyshark.FileCapture(pcap_file, display_filter=disp_filter)
        else:
            capture = pyshark.FileCapture(pcap_file)
        print disp_filter
        length = len([pkt for pkt in capture])
        for _ in range(length):
            print capture[_]

    def wep_shared_auth(self, pcap_file, disp_filter='wlan.fc.type_subtype==11'):
        capture = pyshark.FileCapture(pcap_file, display_filter=disp_filter)
        pkt1 = pkt2 = pkt3 = pkt4 = False
        print "Enterd"
        length = len([pkt for pkt in capture])
        for _ in range(length):
            if hasattr(capture[_], 'wlan_mgt'):
                wlan_pkt = capture[_].wlan_mgt
                if wlan_pkt and  int(wlan_pkt.fixed_auth_alg)==1:
                    seq_pkt = int(wlan_pkt.fixed_auth_seq, 16)
                    if seq_pkt == 1:
                        print(wlan_pkt)
                        pkt1 = True
                    if seq_pkt == 2 and wlan_pkt.tag_challenge_text:
                        print(wlan_pkt)
                        pkt2 = True
                    if seq_pkt == 4 and wlan_pkt.fixed_status_code:
                        print(wlan_pkt)
                        pkt4 = True
            elif hasattr(capture[_], 'wlan'):
                if hasattr(capture[_].wlan, 'wep_icv'):
                    print(capture[_].wlan)
                    pkt3 = True
        return(pkt1 and pkt2 and pkt3 and pkt4)

     def wpa_psk_auth(self, pcap_file, disp_filter='eapol.keydes.type==254'):
        """ Deafult pcap file should be given """
        capture = pyshark.FileCapture(pcap_file, display_filter=disp_filter)
        length = len([pkt for pkt in capture])
        pkt1 = pkt2 = pkt3 = pkt4 = False
        for _ in range(length):
            wlan_pkt = capture[_].eapol
            key_ack = int(capture[_].eapol.wlan_rsna_keydes_key_info_key_ack)
            key_mic = int(capture[_].eapol.wlan_rsna_keydes_key_info_key_mic)
            key_install = int(capture[_].eapol.wlan_rsna_keydes_key_info_install)
            key_data = int(capture[_].eapol.wlan_rsna_keydes_data_len)
            if key_ack == 1 and key_mic == 0:
                print(wlan_pkt)
                pkt1 = True
            if key_mic == 1 and key_data != 0:
                if key_install == 0:
                    print(wlan_pkt)
                    pkt2 = True
                else:
                    print(wlan_pkt)
                    pkt3 = True
            if key_data == 0 and key_mic == 1:
                print(wlan_pkt)
                pkt4 = True
        return(pkt1 and pkt2 and pkt3 and pkt4)

    def wpa2_psk_auth(self, pcap_file, disp_filter='eapol.keydes.type==2'):
        """ Deafult pcap file should be given """
        capture = pyshark.FileCapture(pcap_file, display_filter=disp_filter)
        length = len([pkt for pkt in capture])
        pkt1 = pkt2 = pkt3 = pkt4 = False
        for _ in range(length):
            wlan_pkt = capture[_].eapol
            key_ack = int(capture[_].eapol.wlan_rsna_keydes_key_info_key_ack)
            key_mic = int(capture[_].eapol.wlan_rsna_keydes_key_info_key_mic)
            key_install = int(capture[_].eapol.wlan_rsna_keydes_key_info_install)
            key_data = int(capture[_].eapol.wlan_rsna_keydes_data_len)
            key_secure = int(capture[_].eapol.wlan_rsna_keydes_key_info_secure)
            if key_ack == 1 and key_mic == 0:
                print(wlan_pkt)
                pkt1 = True
            if key_mic == 1 and key_data != 0:
                if key_install == 0:
                    print(wlan_pkt)
                    pkt2 = True
                elif key_secure == 1 and key_install == 1:
                    print(wlan_pkt)
                    pkt3 = True
            if key_data == 0 and key_mic == 1 and key_secure == 1:
                print(wlan_pkt)
                pkt4 = True
        return(pkt1 and pkt2 and pkt3 and pkt4)


    def open_auth(self, pcap_file, disp_filter='wlan.fc.type_subtype==11'):
        """Default pcap file should be given"""
        capture = pyshark.FileCapture(pcap_file, display_filter=disp_filter)
        print disp_filter
        length = len([pkt for pkt in capture])
        pkt1 = pkt2 = False
        for _ in range(length):
            wlan_pkt = capture[_].wlan_mgt
            print wlan_pkt
            if int(wlan_pkt.fixed_auth_alg)==0 and int(wlan_pkt.fixed_auth_seq, 16)==1:
                pkt1 = True
            if int(wlan_pkt.fixed_auth_alg)==0 and int(wlan_pkt.fixed_auth_seq, 16)==2:
                pkt2 = True
        return(pkt1 and pkt2)
            

#obj = Packet_Filter()
#obj.read("open.pcap")
# obj.capture_file("open.pcap")
#name = obj.filters("eapol")
# obj.open_auth("wep_shared.pcap")
# print "hi"
