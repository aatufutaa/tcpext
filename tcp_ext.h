/* tcp_ext.h */

#ifndef TCP_EXT_H
#define TCP_EXT_H

#include "core/object/ref_counted.h"
#include "core/io/stream_peer.h"
#include "core/io/stream_peer_tcp.h"

class TCPExt : public RefCounted {
	GDCLASS(TCPExt, RefCounted);
	 
	Ref<StreamPeerTCP> tcp;

	PackedByteArray write_buf;
	int writer_index;

	PackedByteArray read_buf;
	int reader_index;
	int16_t next_packet_size;

	int readable_bytes;

	PackedByteArray secret;
	bool use_encryption;

	struct rc4_state {
		int x, y, m[256];
	};

	rc4_state encrypt;
	rc4_state decrypt;

	void rc4_setup(rc4_state &state, unsigned char *key, int length);
	void rc4_crypt(rc4_state &state, unsigned char *data, int length);


protected:
    static void _bind_methods();

	Error write_data(const uint8_t *p_data, int p_bytes);

	void read_partial_data(uint8_t *p_buffer, int p_bytes, int &r_received);
	Error read_data(uint8_t *p_buffer, int p_bytes);

public:
	TCPExt();

	void set_tcp(Ref<StreamPeerTCP> p_tcp);
	void set_secret(const PackedByteArray &p_secret);
	void set_use_encryption(bool p_use_encryption);

	void send_packet();

	bool poll_packets();
	bool has_packet();

	void write_byte(int8_t p_val);
	void write_bool(bool p_val);
	void write_short(int16_t p_val);
	void write_int(int32_t p_val);
	void write_long(int64_t p_val);
	void write_float(float p_val);
	void write_string(const String &p_string);
	void write_wide_string(const String &p_string);
	void write_byte_array(const PackedByteArray &p_arr, int length);

	int8_t read_byte();
	bool read_bool();
	int16_t read_short();
	int32_t read_int();
	int64_t read_long();
	float read_float();
	String read_string();
	String read_wide_string();
	PackedByteArray read_byte_array(int size);
};

#endif // TCP_EXT_H
