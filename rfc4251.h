/*
 * rfc4251.h -- implements types from RFC 4251, section 5
 *
 * rfc4251byte		byte
 * rfc4251bool		bool
 * rfc4251uint32	uint32
 * rfc4251uint64	uint64
 * rfc4251string	string, incl. mpint and (without splitting) name-list
 *
 * those structs contain the objects in their RFC 4251 representation,
 * conversions are provided via constructors and cast operators
 *
 * Copyright (C) 2013 Timo Weingärtner <timo@tiwe.de>
 *
 * This file is part of ssh-agent-filter.
 *
 * ssh-agent-filter is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ssh-agent-filter is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ssh-agent-filter.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <vector>
#include <string>
#include <iostream>
#include <arpa/inet.h>	// ntohl() / htonl()
#include <gmpxx.h>

struct rfc4251byte {
	union {
		uint8_t value;
		char buf[1];
	};

	rfc4251byte () = default;
	rfc4251byte (rfc4251byte const &) = default;
	rfc4251byte (rfc4251byte &&) = default;

	inline explicit rfc4251byte (uint8_t v) : value(v) {}

	rfc4251byte & operator= (rfc4251byte const &) = default;
	rfc4251byte & operator= (rfc4251byte &&) = default;

	inline operator uint8_t () const { return value; }
};

inline std::istream & operator>> (std::istream & is, rfc4251byte & x) {
	return is.read(x.buf, sizeof(x.buf));
}

inline std::ostream & operator<< (std::ostream & os, rfc4251byte const & x) {
	return os.write(x.buf, sizeof(x.buf));;
}


struct rfc4251bool {
	union {
		bool value;
		char buf[1];
	};

	rfc4251bool () = default;
	rfc4251bool (rfc4251bool const &) = default;
	rfc4251bool (rfc4251bool &&) = default;

	inline explicit rfc4251bool (uint8_t v) : value(v) {}

	rfc4251bool & operator= (rfc4251bool const &) = default;
	rfc4251bool & operator= (rfc4251bool &&) = default;

	inline operator uint8_t () const { return value; }
};

inline std::istream & operator>> (std::istream & is, rfc4251bool & x) {
	return is.read(x.buf, sizeof(x.buf));
}

inline std::ostream & operator<< (std::ostream & os, rfc4251bool const & x) {
	return os.write(x.buf, sizeof(x.buf));;
}


struct rfc4251uint32 {
	union {
		uint32_t value;
		char buf[4];
	};

	rfc4251uint32 () = default;
	rfc4251uint32 (rfc4251uint32 const &) = default;
	rfc4251uint32 (rfc4251uint32 &&) = default;

	inline explicit rfc4251uint32 (uint32_t v) { value = htonl(v); }

	rfc4251uint32 & operator= (rfc4251uint32 const &) = default;
	rfc4251uint32 & operator= (rfc4251uint32 &&) = default;

	inline operator uint32_t () const { return ntohl(value); }
};

inline std::istream & operator>> (std::istream & is, rfc4251uint32 & x) {
	return is.read(x.buf, sizeof(x.buf));
}

inline std::ostream & operator<< (std::ostream & os, rfc4251uint32 const & x) {
	return os.write(x.buf, sizeof(x.buf));;
}


struct rfc4251uint64 {
	union {
		uint64_t value;
		char buf[8];
	};

	rfc4251uint64 () = default;
	rfc4251uint64 (rfc4251uint64 const &) = default;
	rfc4251uint64 (rfc4251uint64 &&) = default;

	inline explicit rfc4251uint64 (uint64_t v);

	rfc4251uint64 & operator= (rfc4251uint64 const &) = default;
	rfc4251uint64 & operator= (rfc4251uint64 &&) = default;

	inline explicit operator uint64_t () const;
};

inline rfc4251uint64::rfc4251uint64 (uint64_t v) {
	for (int_fast8_t i = 7; i >= 0; --i) {
		buf[i] = v & 0xff;
		v >>= 8;
	}
}

inline rfc4251uint64::operator uint64_t () const {
	uint64_t ret{0};
	for (uint_fast8_t i = 0; i < 8; ++i) {
		ret |= buf[i];
		ret <<= 8;
	}
	return ret;
}

inline std::istream & operator>> (std::istream & is, rfc4251uint64 & x) {
	return is.read(x.buf, sizeof(x.buf));
}

inline std::ostream & operator<< (std::ostream & os, rfc4251uint64 const & x) {
	return os.write(x.buf, sizeof(x.buf));;
}


struct rfc4251string {
	std::vector<char> value;
	
	rfc4251string () = default;
	rfc4251string (rfc4251string const &) = default;
	rfc4251string (rfc4251string &&) = default;
	
	inline explicit rfc4251string (char const *);
	inline explicit rfc4251string (char const *, size_t);
	inline explicit rfc4251string (std::string const & s) : rfc4251string{s.data(), s.size()} {}
	inline explicit rfc4251string (mpz_srcptr);
	inline explicit rfc4251string (mpz_class const & x) : rfc4251string{x.get_mpz_t()} {}

	rfc4251string & operator= (rfc4251string const &) = default;
	rfc4251string & operator= (rfc4251string &&) = default;

	inline operator std::string () const;
	inline operator mpz_class () const;
};

inline rfc4251string::rfc4251string (char const * s) {
	auto len = ntohl(*reinterpret_cast<uint32_t const *>(s));
	value.insert(value.begin(), s, s + 4 + len);
}

inline rfc4251string::rfc4251string (char const * s, size_t l) {
	rfc4251uint32 tmp(l);
	value.insert(value.end(), std::begin(tmp.buf), std::end(tmp.buf));
	value.insert(value.end(), s, s + l);
}

inline rfc4251string::rfc4251string (mpz_srcptr x) {
	if (mpz_sgn(x) == 0)
		value.assign(4, 0);
	else if (mpz_sgn(x) == 1) {
		ssize_t bits = mpz_sizeinbase(x, 2);
		ssize_t bytes = (bits + 7) / 8;
		ssize_t extrabyte = bits % 8 ? 0 : 1; // need extra byte if MSB is 1 to keep it non-negative
		value.resize(4 + bytes + extrabyte);
		*reinterpret_cast<uint32_t *>(value.data()) = htonl(bytes + extrabyte);
		value[4] = 0;
		mpz_export(value.data() + 4 + extrabyte, nullptr, 1, 1, 1, 0, x);
	} else {
		mpz_class tmp(x);
		tmp += 1;
		x = tmp.get_mpz_t();
		ssize_t bits = mpz_sizeinbase(x, 2);
		ssize_t bytes = (bits + 7) / 8;
		ssize_t extrabyte = bits % 8 ? 0 : 1; // need extra byte if MSB is 1 (0 after ^= below) to keep it negative
		value.resize(4 + bytes + extrabyte);
		*reinterpret_cast<uint32_t *>(value.data()) = htonl(bytes + extrabyte);
		value[4] = 0;
		mpz_export(value.data() + 4 + extrabyte, nullptr, 1, 1, 1, 0, x);
		for (auto i = value.data() + 4; i < value.data() + value.size(); ++i)
			*i ^= 0xff;
	}
}

inline rfc4251string::operator std::string () const {
	return std::string(value.begin() + 4, value.end());
}

inline rfc4251string::operator mpz_class () const {
	mpz_class ret;
	mpz_import(ret.get_mpz_t(), value.size() - 4, 1, 1, 1, 0, value.data() + 4);
	if (mpz_sizeinbase(ret.get_mpz_t(), 2) == (value.size() - 4) * 8) { // negative
		mpz_com(ret.get_mpz_t(), ret.get_mpz_t());
		ret += 1;
		mpz_neg(ret.get_mpz_t(), ret.get_mpz_t());
	}
	return ret;
}

inline std::istream & operator>> (std::istream & is, rfc4251string & s) {
	s.value.resize(4);
	if (is.read(s.value.data(), 4)) {
		auto len = ntohl(*reinterpret_cast<uint32_t const *>(s.value.data()));
		s.value.resize(4 + len);
		is.read(s.value.data() + 4, len);
	}
	return is;
}

inline std::ostream & operator<< (std::ostream & os, rfc4251string const & s) {
	return os.write(s.value.data(), s.value.size());
}

inline bool operator== (rfc4251string const & l, rfc4251string const & r) {
	return l.value == r.value;
}

inline bool operator< (rfc4251string const & l, rfc4251string const & r) {
	return l.value < r.value;
}
