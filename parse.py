
import pyshark
import csv
import copy
import collections
import sys
def parse(filename):
    cap = pyshark.FileCapture(filename)
    streams = {}
    for pkt in cap:
        if hasattr(pkt,'tcp') and hasattr(pkt, 'tls'):
            stream_id = str(pkt.tcp.stream)
            if not stream_id in streams:
                streams[stream_id] = {"source_ip": pkt.ip.src, "dest_ip": pkt.ip.dst, "pkt_count": 1, "stream_index": stream_id}
            streams[stream_id]['pkt_count'] += 1

            if not 'tcp' in streams[stream_id]:
                streams[stream_id]['tcp'] = {}
                streams[stream_id]['tcp']['src_port'] = pkt.tcp.srcport
                streams[stream_id]['tcp']['dest_port'] = pkt.tcp.dstport
            if hasattr(pkt, 'tls'):
                payload = get_tls_payload(pkt.tls, streams[stream_id])
                streams[stream_id] = payload
    file = filename.split('/')[-1].split('.')[0] + '.csv'
    f = open('csv/{}'.format(file),'w',encoding='utf8')
    w = csv.DictWriter(f,['stream_index','source_ip','dest_ip','pkt_count','tcp_src_port','tcp_dest_port','tls_version','tls_max_client_tls_version','tls_cipher_suites_length',"tls_is_heartbeat_present","tls_is_record_limit_extension_present","tls_supported_group_length","tls_key_share_length","tls_sig_hash_alg_length",'tls_cert_length','tls_cert_size','tls_cert_begin','tls_cert_end','tls_issuer','tls_algorithm_id','tls_handshake_ciphersuite','tls_handshake_extensions_length','tls_handshake_server_curve_type','tls_handshake_server_named_curve','tls_handshake_echde_server_pubkey_len','tls_handshake_echde_client_pubkey_len','tls_server_name','tls_ja3_hash'])
    w.writeheader()
    records = list(streams.values())
    for record in records:
        document = flatten(copy.deepcopy(record))
        w.writerow(document)
    f.close()
    
def get_tls_payload(tls_payload, stream):
    stream['tls'] = stream['tls'] if 'tls' in stream else {}
    if hasattr(tls_payload, 'handshake_type') and tls_payload.handshake_type == '1':
        stream['tls']['max_client_tls_version'] = '0x304' if hasattr(tls_payload, 'handshake_extensions_supported_versions_len') else '0x303'
        stream['tls']['cipher_suites_length'] = int(tls_payload.handshake_cipher_suites_length) / 2
        # print(len(tls_payload.handshake_extension_type.all_fields))
        for extension_type in tls_payload.handshake_extension_type.all_fields:
            # print(extension_type.get_default_value())
            if extension_type.get_default_value() == '15':
                stream['tls']['is_heartbeat_present'] = True
            else:
                stream['tls']['is_heartbeat_present'] = stream['tls']['is_heartbeat_present'] if hasattr(stream['tls'], 'is_heartbeat_present') else False
        for extension_type in tls_payload.handshake_extension_type.all_fields:
            if extension_type.get_default_value() == '28':
                stream['tls']['is_record_limit_extension_present'] = True
            else:
                stream['tls']['is_record_limit_extension_present'] = stream['tls']['is_record_limit_extension_present'] if hasattr(stream['tls'], 'is_record_limit_extension_present') else False
        stream['tls']['key_share_length'] = len(tls_payload.handshake_extension_key_share_group.all_fields) if hasattr(tls_payload, "handshake_extension_key_share_group") else None
        stream['tls']['sig_hash_alg_length'] = int(tls_payload.handshake_sig_hash_alg_len) / 2
        stream['tls']['supported_group_length'] = int(tls_payload.handshake_extensions_supported_groups_length) / 2

    if hasattr(tls_payload, "handshake_type") and tls_payload.handshake_type == '2':
        stream['tls']['version'] = tls_payload.handshake_extensions_supported_version if hasattr(tls_payload,"handshake_extensions_supported_version") else '0x0303' 
    if hasattr(tls_payload,'handshake_certificates'):
        stream['tls']['cert_length'] = len(tls_payload.handshake_certificate.all_fields)
    if hasattr(tls_payload,'handshake_certificates_length'):
        stream['tls']['cert_size'] = tls_payload.handshake_certificates_length
    if hasattr(tls_payload, 'x509af_utcTime'):
        stream['tls']['cert_begin'] = tls_payload.x509af_utcTime.all_fields[0].get_default_value()
    if hasattr(tls_payload, 'x509af_utcTime'):
        stream['tls']['cert_end'] = tls_payload.x509af_utcTime.all_fields[1].get_default_value()
    # if hasattr(tls_payload, 'x509sat_uTF8String'):
    #     stream['tls']['issuer'] = tls_payload.x509sat_uTF8String
    # if hasattr(tls_payload, 'x509af_algorithm_id'):
    #     stream['tls']['algorithm_id'] = tls_payload.x509af_algorithm_id
    if hasattr(tls_payload, "handshake_ciphersuite"):
        stream['tls']['handshake_ciphersuite'] = tls_payload.handshake_ciphersuite
    if hasattr(tls_payload, 'handshake_extensions_length'):
        stream['tls']['handshake_extensions_length'] = tls_payload.handshake_extensions_length
    ## ecdhe pubkey entities
    # if hasattr(tls_payload,"handshake_server_curve_type"):
    #     stream['tls']['handshake_server_curve_type'] = tls_payload.handshake_server_curve_type
    # if hasattr(tls_payload,"handshake_server_named_curve"):
    #     stream['tls']['handshake_server_named_curve'] = tls_payload.handshake_server_named_curve
    # if hasattr(tls_payload, "handshake_server_point_len"):
    #     stream['tls']['handshake_echde_server_pubkey_len'] = tls_payload.handshake_server_point_len
    # if hasattr(tls_payload, "handshake_client_point_len"):
    #     stream['tls']['handshake_echde_client_pubkey_len'] = tls_payload.handshake_client_point_len        
    if hasattr(tls_payload,"handshake_type"):
        for record in tls_payload.handshake_type.all_fields:
            if record.get_default_value() == '1':
                    stream['tls']['server_name'] = tls_payload.handshake_extensions_server_name
                    stream['tls']['ja3_hash'] = tls_payload.handshake_ja3
    return stream
def flatten(d, parent_key='', sep='_'):
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, collections.MutableMapping):
            items.extend(flatten(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)
if __name__ == '__main__':
    filename = sys.argv[1]
    parse(filename)
# print(flatten({'source_ip': '192.168.64.11', 'dest_ip': '216.137.46.199', 'pkt_count': 16, 'tcp': {'src_port': '49874', 'dest_port': '443'}, 'tls': {'handshake_ciphersuite': '0x1301', 'handshake_extensions_length': '46', 'server_name': 'www.amazon.com', 'ja3_hash': '579ccef312d18482fc42e2b822ca2430', 'cipher_suite_length': '34'}}))
#{'tcp.srcport': '9100', 'tcp.dstport': '40258', 'tcp.port': '9100', 'tcp.stream': '8', 'tcp.completeness': '15', 'tcp.len': '543', 'tcp.seq': '4730', 'tcp.seq_raw': '1401100440', 'tcp.nxtseq': '5273', 'tcp.ack': '3053', 'tcp.ack_raw': '4084368715', 'tcp.hdr_len': '32', 'tcp.flags': '0x0018', 'tcp.flags.res': '0', 'tcp.flags.ns': '0', 'tcp.flags.cwr': '0', 'tcp.flags.ecn': '0', 'tcp.flags.urg': '0', 'tcp.flags.ack': '1', 'tcp.flags.push': '1', 'tcp.flags.reset': '0', 'tcp.flags.syn': '0', 'tcp.flags.fin': '0', 'tcp.flags.str': '·······AP···', 'tcp.window_size_value': '143', 'tcp.window_size': '36608', 'tcp.window_size_scalefactor': '256', 'tcp.checksum': '0x3f45', 'tcp.checksum.status': '2', 'tcp.urgent_pointer': '0', 'tcp.options': '01:01:08:0a:3c:79:b0:10:cf:c3:ae:da', 'tcp.options.nop': '01', 'tcp.option_kind': '1', 'tcp.options.timestamp': '08:0a:3c:79:b0:10:cf:c3:ae:da', 'tcp.option_len': '10', 'tcp.options.timestamp.tsval': '1014607888', 'tcp.options.timestamp.tsecr': '3485707994', '': 'Timestamps', 'tcp.time_relative': '1.238350000', 'tcp.time_delta': '0.103701000', 'tcp.analysis': 'SEQ/ACK analysis', 'tcp.analysis.initial_rtt': '0.037147000', 'tcp.analysis.bytes_in_flight': '543', 'tcp.analysis.push_bytes_sent': '543', 'tcp.payload': '17:03:03:02:1a:7a:ac:a7:c7:76:d2:b1:ba:51:cf:97:32:92:a6:e1:d6:07:0e:1d:3d:40:03:2e:19:5e:c9:b4:af:e9:77:58:40:4a:36:3e:cd:89:6f:9c:1f:94:94:7a:96:94:49:9d:c0:7d:31:25:cd:db:d0:2f:61:59:16:19:ff:37:24:8c:49:80:e9:06:df:8e:60:56:76:aa:a4:8b:02:3b:1f:7c:4a:eb:ba:e6:a9:22:fb:e5:75:48:1a:fb:b6:c1:bc:a9:04:f7:df:c6:85:7d:07:cd:bf:17:a9:19:a2:40:ea:c3:72:55:b3:56:23:bd:9a:e4:e8:2a:75:41:15:ea:21:16:8d:d1:92:40:3a:7e:10:2c:0a:cb:7c:04:66:aa:53:56:c1:fe:53:74:63:df:10:1b:75:b8:19:df:5f:08:50:7f:c4:2d:1f:61:9e:ed:53:2c:9e:ea:03:e8:a5:87:a3:1f:d9:d9:70:5a:fc:06:99:ca:48:11:fe:22:b0:9c:4c:d7:dd:02:db:00:8a:e8:a9:39:6a:d5:97:46:b4:55:1f:3a:90:7d:83:53:43:6f:80:15:7e:6a:7d:7d:6d:04:bf:0e:91:e4:6f:24:72:14:3a:6c:22:30:6c:86:0d:e0:dc:de:57:30:da:76:35:3a:38:2d:87:0a:8f:1a:d8:94:93:db:50:fd:54:5c:99:f5:38:ea:bd:3b:2a:35:8e:8f:d5:d5:32:66:67:95:7c:f3:25:ca:0c:92:c0:55:41:11:37:a2:c3:df:55:c5:1d:68:04:fa:39:8b:27:e8:cf:bd:f0:05:97:49:d2:77:aa:a1:ce:5f:62:da:33:e6:de:7b:8c:b5:9d:0d:b1:f3:6b:e2:c9:df:be:ec:0a:62:b4:eb:c2:ea:ad:38:69:98:6a:58:da:71:47:6b:20:dd:6a:bd:fc:fe:15:9c:c3:1c:61:d2:5b:d9:cd:3c:7a:cb:93:ff:95:9e:2b:ac:5a:cd:ce:65:f8:1c:08:41:cb:4f:ff:44:03:78:33:26:ba:83:a2:25:f2:3b:dc:56:b3:6a:fd:40:3e:1b:aa:27:7b:0b:66:7e:86:4a:90:03:11:58:00:47:0c:ba:7f:3d:3b:0d:27:7f:7e:4d:11:9c:f1:4d:93:01:ad:f3:6a:f6:e8:d3:cd:e7:37:2d:d2:39:1c:5b:6f:d3:30:58:52:29:20:84:7b:43:a7:c4:45:70:78:a7:4a:a9:81:f9:63:d5:b0:1f:3a:40:d7:c2:f0:b1:42:45:15:87:34:c9:28:31:1f:30:35:8d:ab:42:e6:58:89:4f:21:6a:1c:00:c3:78:9e:ac:c9:26:dd:dd:5d:10:41:be:db:a6:91:e2:3d:7d:46:8a:50:f1:7b:78:1b:82:f0:ae:c0:01:e1:32:61:35:89:fa:4e:13:b3:08:86:a8:18'}}
#{'raw_mode': False, '_layer_name': 'tcp', '_all_fields': {'tcp.srcport': '9000', 'tcp.dstport': '54018', 'tcp.port': '9000', 'tcp.stream': '9', 'tcp.completeness': '15', 'tcp.len': '0', 'tcp.seq': '3657', 'tcp.seq_raw': '2760720668', 'tcp.nxtseq': '3657', 'tcp.ack': '1969', 'tcp.ack_raw': '2155389800', 'tcp.hdr_len': '32', 'tcp.flags': '0x0010', 'tcp.flags.res': '0', 'tcp.flags.ns': '0', 'tcp.flags.cwr': '0', 'tcp.flags.ecn': '0', 'tcp.flags.urg': '0', 'tcp.flags.ack': '1', 'tcp.flags.push': '0', 'tcp.flags.reset': '0', 'tcp.flags.syn': '0', 'tcp.flags.fin': '0', 'tcp.flags.str': '·······A····', 'tcp.window_size_value': '22', 'tcp.window_size': '45056', 'tcp.window_size_scalefactor': '2048', 'tcp.checksum': '0x2bd3', 'tcp.checksum.status': '2', 'tcp.urgent_pointer': '0', 'tcp.options': '01:01:08:0a:e7:e7:9f:ba:57:c7:8d:12', 'tcp.options.nop': '01', 'tcp.option_kind': '1', 'tcp.options.timestamp': '08:0a:e7:e7:9f:ba:57:c7:8d:12', 'tcp.option_len': '10', 'tcp.options.timestamp.tsval': '3890716602', 'tcp.options.timestamp.tsecr': '1472695570', '': 'Timestamps', 'tcp.time_relative': '0.238290000', 'tcp.time_delta': '0.072684000', 'tcp.analysis': 'SEQ/ACK analysis', 'tcp.analysis.acks_frame': '403', 'tcp.analysis.ack_rtt': '0.072684000', 'tcp.analysis.initial_rtt': '0.032369000'}}
#{'raw_mode': False, '_layer_name': 'tcp', '_all_fields': {'tcp.srcport': '40258', 'tcp.dstport': '9100', 'tcp.port': '40258', 'tcp.stream': '8', 'tcp.completeness': '15', 'tcp.len': '0', 'tcp.seq': '3053', 'tcp.seq_raw': '4084368715', 'tcp.nxtseq': '3053', 'tcp.ack': '5273', 'tcp.ack_raw': '1401100983', 'tcp.hdr_len': '32', 'tcp.flags': '0x0010', 'tcp.flags.res': '0', 'tcp.flags.ns': '0', 'tcp.flags.cwr': '0', 'tcp.flags.ecn': '0', 'tcp.flags.urg': '0', 'tcp.flags.ack': '1', 'tcp.flags.push': '0', 'tcp.flags.reset': '0', 'tcp.flags.syn': '0', 'tcp.flags.fin': '0', 'tcp.flags.str': '·······A····', 'tcp.window_size_value': '501', 'tcp.window_size': '64128', 'tcp.window_size_scalefactor': '128', 'tcp.checksum': '0xd3e9', 'tcp.checksum.status': '2', 'tcp.urgent_pointer': '0', 'tcp.options': '01:01:08:0a:cf:c3:af:5d:3c:79:b0:10', 'tcp.options.nop': '01', 'tcp.option_kind': '1', 'tcp.options.timestamp': '08:0a:cf:c3:af:5d:3c:79:b0:10', 'tcp.option_len': '10', 'tcp.options.timestamp.tsval': '3485708125', 'tcp.options.timestamp.tsecr': '1014607888', '': 'Timestamps', 'tcp.time_relative': '1.238365000', 'tcp.time_delta': '0.000015000', 'tcp.analysis': 'SEQ/ACK analysis', 'tcp.analysis.acks_frame': '404', 'tcp.analysis.ack_rtt': '0.000015000', 'tcp.analysis.initial_rtt': '0.037147000'}}
#{'raw_mode': False, '_layer_name': 'tcp', '_all_fields': {'tcp.srcport': '40258', 'tcp.dstport': '9100', 'tcp.port': '40258', 'tcp.stream': '8', 'tcp.completeness': '15', 'tcp.len': '543', 'tcp.seq': '3053', 'tcp.seq_raw': '4084368715', 'tcp.nxtseq': '3596', 'tcp.ack': '5273', 'tcp.ack_raw': '1401100983', 'tcp.hdr_len': '32', 'tcp.flags': '0x0018', 'tcp.flags.res': '0', 'tcp.flags.ns': '0', 'tcp.flags.cwr': '0', 'tcp.flags.ecn': '0', 'tcp.flags.urg': '0', 'tcp.flags.ack': '1', 'tcp.flags.push': '1', 'tcp.flags.reset': '0', 'tcp.flags.syn': '0', 'tcp.flags.fin': '0', 'tcp.flags.str': '·······AP···', 'tcp.window_size_value': '501', 'tcp.window_size': '64128', 'tcp.window_size_scalefactor': '128', 'tcp.checksum': '0xf1da', 'tcp.checksum.status': '2', 'tcp.urgent_pointer': '0', 'tcp.options': '01:01:08:0a:cf:c3:af:5d:3c:79:b0:10', 'tcp.options.nop': '01', 'tcp.option_kind': '1', 'tcp.options.timestamp': '08:0a:cf:c3:af:5d:3c:79:b0:10', 'tcp.option_len': '10', 'tcp.options.timestamp.tsval': '3485708125', 'tcp.options.timestamp.tsecr': '1014607888', '': 'Timestamps', 'tcp.time_relative': '1.238746000', 'tcp.time_delta': '0.000381000', 'tcp.analysis': 'SEQ/ACK analysis', 'tcp.analysis.initial_rtt': '0.037147000', 'tcp.analysis.bytes_in_flight': '543', 'tcp.analysis.push_bytes_sent': '543',

#{'raw_mode': False, '_layer_name': 'tls', '_all_fields': {'tls.record': 'TLSv1 Record Layer: Handshake Protocol: Client Hello', 'tls.record.content_type': '22', 'tls.record.version': '0x0301', 'tls.record.length': '185', 'tls.handshake': 'Handshake Protocol: Client Hello', 'tls.handshake.type': '1', 'tls.handshake.length': '181', 'tls.handshake.version': '0x0303', 'tls.handshake.random': '5b:e2:64:5a:3b:62:77:ff:32:92:15:3a:73:cd:d5:e1:07:f9:71:d1:eb:ab:ef:6c:05:0f:a0:da:4b:81:72:d3', 'tls.handshake.random_time': 'Nov  7, 2018 04:04:42.000000000 GMT', 'tls.handshake.random_bytes': '3b:62:77:ff:32:92:15:3a:73:cd:d5:e1:07:f9:71:d1:eb:ab:ef:6c:05:0f:a0:da:4b:81:72:d3', 'tls.handshake.session_id_length': '0', 'tls.handshake.cipher_suites_length': '28', 'tls.handshake.ciphersuites': 'Cipher Suites (14 suites)', 'tls.handshake.ciphersuite': '0xc02b', 'tls.handshake.comp_methods_length': '1', 'tls.handshake.comp_methods': 'Compression Methods (1 method)', 'tls.handshake.comp_method': '0', 'tls.handshake.extensions_length': '112', '': 'Extension: server_name (len=23)', 'tls.handshake.extension.type': '0', 'tls.handshake.extension.len': '23', 'tls.handshake.extensions_server_name_list_len': '21', 'tls.handshake.extensions_server_name_type': '0', 'tls.handshake.extensions_server_name_len': '18', 'tls.handshake.extensions_server_name': 'www.vunlpqnz6y.com', 'tls.handshake.extensions_ec_point_formats_length': '3', 'tls.handshake.extensions_ec_point_formats': 'Elliptic curves point formats (3)', 'tls.handshake.extensions_ec_point_format': '0', 'tls.handshake.extensions_supported_groups_length': '26', 'tls.handshake.extensions_supported_groups': 'Supported Groups (13 groups)', 'tls.handshake.extensions_supported_group': '0x0017', 'tls.handshake.extension.data': 'Data (0 bytes)', 'tls.handshake.sig_hash_alg_len': '30', 'tls.handshake.sig_hash_algs': 'Signature Hash Algorithms (15 algorithms)', 'tls.handshake.sig_hash_alg': '0x0601', 'tls.handshake.sig_hash_hash': '6', 'tls.handshake.sig_hash_sig': '1', 'tls.handshake.extension.heartbeat.mode': '1', 'tls.handshake.ja3_full': '771,49195-49199-49196-49200-49162-49161-49171-49172-51-57-47-53-10-255,0-11-10-35-13-15,23-25-28-27-24-26-22-14-13-11-12-9-10,0-1-2', 'tls.handshake.ja3': '83d60721ecc423892660e275acc4dffd'}}