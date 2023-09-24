/* tcp_ext.cpp */

#include "tcp_ext.h"
#include "core/io/marshalls.h"

TCPExt::TCPExt() {
}

void TCPExt::set_tcp(Ref<StreamPeerTCP> p_tcp) {
	this->tcp = p_tcp;

	this->write_buf = PackedByteArray{};
	this->write_buf.resize(1024);
	this->writer_index = 2;

	this->read_buf = PackedByteArray{};
	this->read_buf.resize(1024);
	this->reader_index = 0;
	this->next_packet_size = 0;

	this->readable_bytes = 0;

	this->use_encryption = false;
}

void TCPExt::set_secret(const PackedByteArray &p_secret) {
	this->secret = p_secret;
	this->rc4_setup(this->encrypt,(unsigned char *) p_secret.ptr(), p_secret.size());
	this->rc4_setup(this->decrypt, (unsigned char*)p_secret.ptr(), p_secret.size());
}

void TCPExt::set_use_encryption(bool p_use_encryption) {
	this->use_encryption = p_use_encryption;
}

void TCPExt::send_packet() {
	int packet_size = this->writer_index - 2;
	this->writer_index = 0;
	this->write_short(packet_size);

	if (this->use_encryption) {
		this->rc4_crypt(this->encrypt, (unsigned char *)this->write_buf.ptr() + 2, packet_size);
	}
	this->tcp->put_data((uint8_t *)this->write_buf.ptrw(), packet_size + 2);

	this->writer_index = 2;
}

bool TCPExt::has_packet() {
	if (this->next_packet_size > 0) {
		if (this->readable_bytes >= this->next_packet_size) {
			if (this->use_encryption) {
				this->rc4_crypt(this->decrypt, (unsigned char *)this->read_buf.ptr() + this->reader_index, this->next_packet_size);
			}
			this->next_packet_size = 0;
			return true;
		}
	} else if (this->readable_bytes > 2) {
		this->next_packet_size = this->read_short();
		return this->has_packet();
	}
	if (this->reader_index > 0) {
		if (readable_bytes > 0) {
			uint8_t *w = this->read_buf.ptrw();
			memcpy(&w[0], w + this->reader_index, readable_bytes);
		}
		this->reader_index = 0;
	}
	return false;
}

bool TCPExt::poll_packets() {
	int readable = this->tcp->get_available_bytes();
	if (readable <= 0) {
		return false;
	}

	int new_size = this->readable_bytes + readable;
	if (this->read_buf.size() < new_size) {
		this->read_buf.resize(new_size);
	}

	this->tcp->get_data((uint8_t *)(this->read_buf.ptrw() + this->readable_bytes), readable);
	this->readable_bytes += readable;

	return true;
}

Error TCPExt::write_data(const uint8_t *p_data, int p_bytes) {
	if (p_bytes <= 0) {
		return OK;
	}

	if (this->writer_index + p_bytes > this->write_buf.size()) {
		write_buf.resize(this->writer_index + p_bytes);
	}

	uint8_t *w = this->write_buf.ptrw();
	memcpy(&w[this->writer_index], p_data, p_bytes);

	this->writer_index += p_bytes;
	return OK;
}

void TCPExt::write_byte(int8_t p_val) {
	this->write_data((const uint8_t *)&p_val, 1);
}

void TCPExt::write_bool(bool p_val) {
	this->write_byte(p_val);
}

void TCPExt::write_short(int16_t p_val) {
	p_val = BSWAP16(p_val);
	uint8_t buf[2];
	encode_uint16(p_val, buf);
	this->write_data(buf, 2);
}

void TCPExt::write_int(int32_t p_val) {
	p_val = BSWAP32(p_val);
	uint8_t buf[4];
	encode_uint32(p_val, buf);
	this->write_data(buf, 4);
}

void TCPExt::write_float(float p_val) {
	uint8_t buf[4];
	encode_float(p_val, buf);
	uint32_t *p32 = (uint32_t *)buf;
	*p32 = BSWAP32(*p32);
	this->write_data(buf, 4);
}

void TCPExt::write_string(const String &p_string) {
	CharString cs = p_string.utf8();
	this->write_short(cs.length());
	this->write_data((const uint8_t *)cs.get_data(), cs.length());
}

void TCPExt::write_wide_string(const String &p_string) {
	CharString cs = p_string.ascii();
	this->write_short(cs.length());
	this->write_data((const uint8_t *)cs.get_data(), cs.length());
}

void TCPExt::write_byte_array(const PackedByteArray &p_arr, int length) {
	this->write_data((uint8_t*)p_arr.ptr(), length);
}

void TCPExt::read_partial_data(uint8_t *p_buffer, int p_bytes, int &r_received) {
	if (this->reader_index + p_bytes > this->read_buf.size()) {
		r_received = this->read_buf.size() - this->reader_index;
		if (r_received <= 0) {
			r_received = 0;
			return; //you got 0
		}
	} else {
		r_received = p_bytes;
	}

	const uint8_t *r = this->read_buf.ptr();
	memcpy(p_buffer, r + this->reader_index, r_received);

	this->reader_index += r_received;
	this->readable_bytes -= r_received;
}

Error TCPExt::read_data(uint8_t *p_buffer, int p_bytes) {
	int recv;
	this->read_partial_data(p_buffer, p_bytes, recv);
	if (recv != p_bytes) {
		return ERR_INVALID_PARAMETER;
	}

	return OK;
}

int8_t TCPExt::read_byte() {
	uint8_t buf[1];
	this->read_data(buf, 1);
	return buf[0];
}

bool TCPExt::read_bool() {
	return this->read_byte();
}

int16_t TCPExt::read_short() {
	uint8_t buf[2];
	this->read_data(buf, 2);
	uint16_t r = decode_uint16(buf);
	r = BSWAP16(r);
	return r;
}

uint16_t TCPExt::read_ushort() {
	uint8_t buf[2];
	this->read_data(buf, 2);
	uint16_t r = decode_uint16(buf);
	r = BSWAP16(r);
	return r;
}

int32_t TCPExt::read_int() {
	uint8_t buf[4];
	this->read_data(buf, 4);
	uint32_t r = decode_uint32(buf);
	r = BSWAP32(r);
	return r;
}

float TCPExt::read_float() {
	uint8_t buf[4];
	this->read_data(buf, 4);
	uint32_t *p32 = (uint32_t *)buf;
	*p32 = BSWAP32(*p32);
	return decode_float(buf);
}

String TCPExt::read_string() {
	int p_bytes = this->read_short();

	ERR_FAIL_COND_V(p_bytes < 0, String());

	Vector<uint8_t> buf;
	Error err = buf.resize(p_bytes);
	ERR_FAIL_COND_V(err != OK, String());
	err = read_data(buf.ptrw(), p_bytes);
	ERR_FAIL_COND_V(err != OK, String());

	String ret;
	ret.parse_utf8((const char *)buf.ptr(), buf.size());
	return ret;
}

String TCPExt::read_wide_string() {
	int p_bytes = this->read_short();

	ERR_FAIL_COND_V(p_bytes < 0, String());

	Vector<char> buf;
	Error err = buf.resize(p_bytes + 1);
	ERR_FAIL_COND_V(err != OK, String());
	err = read_data((uint8_t *)&buf[0], p_bytes);
	ERR_FAIL_COND_V(err != OK, String());
	buf.write[p_bytes] = 0;
	return buf.ptr();
}

PackedByteArray TCPExt::read_byte_array(int size) {
	PackedByteArray ret{};
	Error err = ret.resize(size);
	ERR_FAIL_COND_V(err != OK, ret);
	this->read_data((uint8_t *)ret.ptr(), size);
	return ret;
}

void TCPExt::_bind_methods() {
	ClassDB::bind_method(D_METHOD("set_tcp", "value"), &TCPExt::set_tcp);

	ClassDB::bind_method(D_METHOD("set_secret", "value"), &TCPExt::set_secret);
	ClassDB::bind_method(D_METHOD("set_use_encryption", "value"), &TCPExt::set_use_encryption);

	ClassDB::bind_method(D_METHOD("send_packet"), &TCPExt::send_packet);
	ClassDB::bind_method(D_METHOD("poll_packets"), &TCPExt::poll_packets);
	ClassDB::bind_method(D_METHOD("has_packet"), &TCPExt::has_packet);

	ClassDB::bind_method(D_METHOD("write_byte", "value"), &TCPExt::write_byte);
	ClassDB::bind_method(D_METHOD("write_bool", "value"), &TCPExt::write_bool);
	ClassDB::bind_method(D_METHOD("write_short", "value"), &TCPExt::write_short);
	ClassDB::bind_method(D_METHOD("write_int", "value"), &TCPExt::write_int);
	ClassDB::bind_method(D_METHOD("write_float", "value"), &TCPExt::write_float);
	ClassDB::bind_method(D_METHOD("write_string", "value"), &TCPExt::write_string);
	ClassDB::bind_method(D_METHOD("write_wide_string", "value"), &TCPExt::write_wide_string);
	ClassDB::bind_method(D_METHOD("write_byte_array", "value", "length"), &TCPExt::write_byte_array);
	
	ClassDB::bind_method(D_METHOD("read_byte"), &TCPExt::read_byte);
	ClassDB::bind_method(D_METHOD("read_bool"), &TCPExt::read_bool);
	ClassDB::bind_method(D_METHOD("read_short"), &TCPExt::read_short);
	ClassDB::bind_method(D_METHOD("read_ushort"), &TCPExt::read_ushort);
	ClassDB::bind_method(D_METHOD("read_int"), &TCPExt::read_int);
	ClassDB::bind_method(D_METHOD("read_float"), &TCPExt::read_float);
	ClassDB::bind_method(D_METHOD("read_string"), &TCPExt::read_string);
	ClassDB::bind_method(D_METHOD("read_wide_string"), &TCPExt::read_wide_string);
	ClassDB::bind_method(D_METHOD("read_byte_array", "length"), &TCPExt::read_byte_array);
}


void TCPExt::rc4_setup(rc4_state &s, unsigned char *key, int length) {
	int i, j, k, *m, a;

	s.x = 0;
	s.y = 0;
	m = s.m;

	for (i = 0; i < 256; i++) {
		m[i] = i;
	}

	j = k = 0;

	for (i = 0; i < 256; i++) {
		a = m[i];
		j = (unsigned char)(j + a + key[k]);
		m[i] = m[j];
		m[j] = a;
		if (++k >= length)
			k = 0;
	}
}

void TCPExt::rc4_crypt(rc4_state &s, unsigned char *data, int length) {
	int i, x, y, *m, a, b;

	x = s.x;
	y = s.y;
	m = s.m;

	for (i = 0; i < length; i++) {
		x = (unsigned char)(x + 1);
		a = m[x];
		y = (unsigned char)(y + a);
		m[x] = b = m[y];
		m[y] = a;
		data[i] ^= m[(unsigned char)(a + b)];
	}

	s.x = x;
	s.y = y;
}
