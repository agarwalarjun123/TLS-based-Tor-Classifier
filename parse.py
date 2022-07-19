
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
    w = csv.DictWriter(f,['stream_index','source_ip','dest_ip','pkt_count','tcp_src_port','tcp_dest_port','tls_version','tls_max_client_tls_version','tls_cipher_suites_length',"tls_is_heartbeat_present","tls_is_record_limit_extension_present","tls_supported_group_length","tls_key_share_length","tls_selected_group","tls_ec_points_format_length","tls_sig_hash_alg_length",'tls_cert_length','tls_cert_size','tls_cert_begin','tls_cert_end','tls_issuer','tls_algorithm_id','tls_handshake_ciphersuite','tls_handshake_extensions_length','tls_server_name','tls_ja3_hash'])
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
        for extension_type in tls_payload.handshake_extension_type.all_fields:
            if extension_type.get_default_value() == '15':
                stream['tls']['is_heartbeat_present'] = True
            else:
                stream['tls']['is_heartbeat_present'] = stream['tls']['is_heartbeat_present'] if hasattr(stream['tls'], 'is_heartbeat_present') else False
        stream['tls']['is_record_limit_extension_present'] = False
        for extension_type in tls_payload.handshake_extension_type.all_fields:
            if extension_type.get_default_value() == '28':
                stream['tls']['is_record_limit_extension_present'] = True
        stream['tls']['key_share_length'] = len(tls_payload.handshake_extensions_key_share_group.all_fields) if hasattr(tls_payload, "handshake_extensions_key_share_group") else None
        stream['tls']['supported_group_length'] = int(tls_payload.handshake_extensions_supported_groups_length) / 2
        stream['tls']['sig_hash_alg_length'] = int(tls_payload.handshake_sig_hash_alg_len) / 2
        
        if hasattr(tls_payload, 'handshake_extensions_ec_point_formats_length'):
            stream['tls']['ec_points_format_length'] = int(tls_payload.handshake_extensions_ec_point_formats_length)
    if hasattr(tls_payload, 'handshake_extensions_key_share_group') and tls_payload.handshake_type == '2':
            stream['tls']['selected_group'] = tls_payload.handshake_extensions_key_share_group
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