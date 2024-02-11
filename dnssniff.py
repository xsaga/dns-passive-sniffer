import time
import queue
import signal
from collections import deque
from threading import Event, Thread

from scapy.all import AsyncSniffer, IP, DNS
from scapy.layers.dns import dnstypes, dnsclasses


def dns_sniff_callback(query_buff, response_buff, pkt):
    """
    Push DNS query packets to the query_buff deque, and DNS response packets to the response_buff queue.
    Called by scapy for each packet.
    """
    # https://en.wikipedia.org/wiki/Domain_Name_System
    # https://scapy.readthedocs.io/en/latest/api/scapy.layers.dns.html
    if pkt.qr == 0:
        # query
        query_buff.append(pkt)
    else:
        # reply
        response_buff.put(pkt)
    # return pkt.summary()


def dns_sniffer(query_buff, response_buff, die_event):
    """Start asyncronous packet sniffer and wait until die_event signal is set."""
    print("[ sniffer ] Starting dns sniffer.")

    # sniff(filter="udp and port 53",
    #       prn=lambda p: dns_sniff_callback(query_buff, response_buff, p))

    sniffer = AsyncSniffer(filter="udp and port 53",
                           prn=lambda p: dns_sniff_callback(query_buff, response_buff, p))

    sniffer.start()

    while not die_event.is_set():
        die_event.wait(1)

    sniffer.stop()
    print("[ sniffer ] Sniffer end.")


def deltatime_qry_ans(query, response):
    """Return the time delta between response and query"""
    return response.time - query.time


def dns_packet_to_str(pkt):
    """String representation of a DNS packet"""
    # https://www.ietf.org/rfc/rfc1035.txt
    # return str(pkt[DNS])
    qr_map = {0: "QRY",  # query
              1: "ANS"}  # response
    opcode_map = {0: "std", # standard
                  1: "inv",  # inverse
                  2: "stat"}   # status
    opcode_map.update({i:f"reserved {i}" for i in range(3,16)})

    aa_map = {0: "",     # non authoritative
              1: "AUTH"} # authoritative

    rcode_map = {0: "OK",        # no error
                 1: "fmt ERR!",  # format error
                 2: "srv FAIL!", # server failure
                 3: "name ERR!", # name error
                 4: "not impl!", # not implemented
                 5: "refused!"}  # refused
    rcode_map.update({i:f"error {i}!" for i in range(6,16)})

    if pkt.qr==0:
        # query
        res = f"{opcode_map[pkt.opcode]} {qr_map[pkt.qr]} to {pkt[IP].dst:15}: "
        res += f" {pkt.qdcount} quer{"y" if pkt.qdcount==1 else "ies"} "
        q_section = [pkt.qd] if not isinstance(pkt.qd, list) else pkt.qd

        for q in q_section:
            res += f" {dnsclasses[q.qclass]} {dnstypes[q.qtype]} {q.qname.decode('utf-8')} ?"

    else:
        # answer
        res = f"{aa_map[pkt.aa]} {qr_map[pkt.qr]} {rcode_map[pkt.rcode]} from {pkt[IP].src:15}: "
        # AN answer section
        res += f"AN count {pkt.ancount} "
        for i in range(pkt.ancount):
            a = pkt.an[i]
            res += f" {dnsclasses[a.rclass]} {dnstypes[a.type]} {a.rrname.decode('utf-8')} is {a.rdata};"
        # NS authority section
        res += f"| NS count {pkt.nscount} "
        for i in range(pkt.nscount):
            a = pkt.ns[i]
            res += f" {dnsclasses[a.rclass]} {dnstypes[a.type]} {a.rrname.decode('utf-8')} primary nameserver is {a.mname.decode('utf-8')};"
        # AR additional data section
        res += f"| AR count {pkt.arcount} "
        for i in range(pkt.arcount):
            a = pkt.ar[i]
            res += f" {dnsclasses[a.rclass]} {dnstypes[a.type]} {a.rrname.decode('utf-8')} is {a.rdata};"

    return res

def process_packets(query_buff, response_buff, die_event):
    """Match DNS response with corresponding query packet and process the pair."""
    print("[processor] Starting packet processor.")
    while not die_event.is_set():
        # TODO. If die_event is set, process all buffers
        try:
            response = response_buff.get(timeout=1)
        except queue.Empty:
            continue

        # match response with the query
        matched_query = None
        for q in query_buff:
            if response.answers(q):
                matched_query = q
                break

        if matched_query:
            query_buff.remove(matched_query)
            print(f"[processor] [{deltatime_qry_ans(matched_query, response)*1000:.2f} ms]\t{dns_packet_to_str(matched_query)}\t<-->\t{dns_packet_to_str(response)}")
        else:
            print("[processor] Unsolicited DNS response!")
    print("[processor] Process packet end.")


def main():
    die_event = Event()
    queries = deque()
    responses = queue.Queue()

    producer_th = Thread(target=dns_sniffer, args=(queries, responses, die_event))
    consumer_th = Thread(target=process_packets, args=(queries, responses, die_event))

    die_event.clear()
    consumer_th.start()
    producer_th.start()

    while not die_event.is_set():
        try:
            die_event.wait(1)
        except KeyboardInterrupt:
            die_event.set()

    producer_th.join()
    consumer_th.join()
    print(f"[  main   ] {len(queries)} packets left in queries queue")
    print(f"[  main   ] {responses.qsize()} packets left in responses queue")
    print("[  main   ] End.")

if __name__ == "__main__":
    main()
